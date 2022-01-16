import os
import random
import sys
import threading
from copy import deepcopy
from subprocess import Popen
from subprocess import PIPE

import torch
from torch.multiprocessing import Pool, Value
from torch.multiprocessing import set_start_method

from fuzz.resolve import hoisting
from fuzz.resolve import resolve_id
from fuzz.resolve import update_builtins
from fuzz.resolve_bug import ResolveBug
from utils import data2tensor
from utils import get_node_type
from utils import hash_frag
from utils import init_worker
from utils import is_single_node
from utils import is_node_list
from utils import kill_proc
from utils import load_pickle
from utils import pool_map
from utils import trim_seed_name
from utils.harness import Harness
from utils.logger import print_msg
from utils.node import PROP_DICT
from utils.node import TERM_TYPE
from utils.node import get_define_node
from utils.node import get_load_node
from utils.print import CodePrinter

import signal
from datetime import datetime
from functools import partial
import schedule

class Fuzzer:
  def __init__(self, proc_idx, conf):
    self._eng_path = conf.eng_path
    self._eng_name = conf.eng_name
    self._max_ins = conf.max_ins
    self._num_gpu = conf.num_gpu
    self._model_path = conf.model_path
    self._opt = conf.opt
    self._seed_dir = conf.seed_dir
    self._bug_dir = os.path.join(conf.bug_dir,
                                 'proc.%d' % proc_idx)
    self._cov_dir = conf.cov_dir
    self._timeout = conf.timeout
    self._top_k = conf.top_k

    self._harness = Harness(conf.seed_dir)
    if not os.path.exists(self._cov_dir):
      os.makedirs(self._cov_dir)
    if not os.path.exists(self._bug_dir):
      os.makedirs(self._bug_dir)
    log_path = os.path.join(self._bug_dir,
                            'logs.csv')
    self._crash_log = open(log_path, 'ab', 0)
    cov_path = os.path.join(self._bug_dir,
                            'cov.csv')
    self._cov_log = open(cov_path, 'wb', 0)

    seed, data = load_data(conf)
    (self._seed_dict,
     self._frag_list,
     self._new_seed_dict,
     _) = seed
    (self._new_frag_list,
     self._new_frag_dict,
     self._oov_pool,
     self._type_dict) = data

    self._cov_set = set()

    self.assign_gpu(proc_idx)
    update_builtins(conf.eng_path)

  def append_frag(self, cand_list, valid_type, root, stack):
    # Try all fragments in top k
    while len(cand_list) > 0:
      cand_idx = random.choice(cand_list)
      cand_frag = self._new_frag_list[cand_idx]

      if type(cand_frag) == dict:
        cand_type = get_node_type(cand_frag)
      else:
        cand_type = cand_frag

      if cand_type == valid_type:
        parent_idx, frag_type = self.expand_ast(cand_frag,
                                                stack, root)
        frag = [cand_idx]
        return True, frag, parent_idx, frag_type
      else:
        cand_list.remove(cand_idx)
    return False, None, None, None

  def assign_gpu(self, proc_idx):
    gpu_idx = proc_idx % self._num_gpu
    os.environ['CUDA_VISIBLE_DEVICES'] = '%d' % gpu_idx

  def build_ast(self, node, stack, frag):
    node_type = get_node_type(node)
    for key in PROP_DICT[node_type]:
      if key not in node: continue
      child = node[key]

      # If it has a single child
      if is_single_node(child):
        if not is_pruned(child):
          frag = self.build_ast(child, stack, frag)
        # Expand the frag
        elif frag:
          self.push(stack, frag)
          node[key] = frag
          return None
      # If it has multiple children
      elif is_node_list(child):
        for idx, _child in enumerate(child):
          if _child == None:
            continue
          elif not is_pruned(_child):
            frag = self.build_ast(child[idx], stack, frag)
          # Expand the frag
          elif frag:
            self.push(stack, frag)
            child[idx] = frag
            return None
    return frag

  def build_seed_tree(self, seed_name, frag_seq):
    max_idx = len(frag_seq) - 1
    idx = random.randint(2, max_idx)

    # Find subtree to be pruned
    pre_seq = frag_seq[:idx]
    pruned_seq = frag_seq[idx:]
    root, post_seq = self.build_subtree(pruned_seq)

    # Build the seed tree
    frags = pre_seq + [-1] + post_seq
    stack = []
    root, _ = self.build_subtree(frags, stack)
    parent_idx, frag_type = stack.pop(0)

    # Get OoV version of frags
    pre_seq, _ = self._new_seed_dict[seed_name]
    pre_seq = pre_seq[:idx]
    return root, pre_seq, parent_idx, frag_type

  def build_subtree(self, frag_seq, stack=None):
    frag_idx = frag_seq.pop(0)
    root = self.idx2frag(frag_idx)
    self.traverse(root, frag_seq, stack)
    return root, frag_seq

  def exec_eng(self, js_path):
    cmd = [self._eng_path] + self._opt + [js_path]
    proc = Popen(cmd, cwd = self._seed_dir,
                 stdout = PIPE, stderr = PIPE)
    timer = threading.Timer(self._timeout, kill_proc, [proc])
    timer.start()
    stdout, stderr = proc.communicate()
    timer.cancel()
    cov_path = os.path.join(self._cov_dir, self._eng_name + '.' + str(proc.pid) + '.sancov')
    error = str(stderr)
    if proc.returncode in [-4, -7, -11]:
      log = [self._eng_path] + self._opt
      log += [js_path, str(proc.returncode), str(proc.pid), datetime.now().strftime("%Y%m%d%H%M%S"), error]
      log = str.encode(','.join(log) + '\n')
      self._crash_log.write(log)
      msg = 'Found a bug (%s)' % js_path
      print_msg(msg, 'INFO')
      with pass_exec_count_shared.get_lock():
        pass_exec_count_shared.value += 1
    elif (proc.returncode == 1 or
      (self._eng_name == "ch" and ('SyntaxError:' in error or
      'ReferenceError:' in error or
      'TypeError:' in error or
      'RangeError:' in error or
      'URIError:' in error or
      'Error in opening file:' in error))):
      os.remove(js_path)
      if os.path.exists(cov_path):
        os.remove(cov_path)
    else:
      os.remove(js_path)
      cmd_sancov = ['sancov', '-print', cov_path]
      proc_sancov = Popen(cmd_sancov, cwd = self._cov_dir,
                  stdout = PIPE, stderr = PIPE)
      cov_list = proc_sancov.communicate()[0].decode("utf-8").strip().split()
      new_cov_set = set(cov_list)
      score = len(new_cov_set - self._cov_set)
      if score > 0:
        self._cov_set |= new_cov_set
      if os.path.exists(cov_path):
        os.remove(cov_path)
      with pass_exec_count_shared.get_lock():
        pass_exec_count_shared.value += 1
    with total_exec_count_shared.get_lock():
      total_exec_count_shared.value += 1

  def expand_ast(self, frag, stack, root):
    # Out-of-vocabulary
    if type(frag) == str:
      frag_type = frag
      frag = random.choice(self._oov_pool[frag_type])

    frag = deepcopy(frag)
    self.build_ast(root, stack, frag)

    if len(stack) == 0:
      return None, None
    else:
      parent_idx, frag_type = stack.pop()
      return parent_idx, frag_type

  def frag2idx(self, frag):
    node_type = get_node_type(frag)
    hash_val = hash_frag(frag)
    if hash_val in self._new_frag_dict:
      return self._new_frag_dict[hash_val]
    else:
      return self._new_frag_dict[node_type]

  def fuzz(self):
    model = load_model(self._model_path)

    printer = CodePrinter(self._bug_dir)

    schedule.every(48).hours.do(self.log_cov)

    while True:
      schedule.run_pending()
      js_path = self.gen_code(printer, model)
      if js_path == None: continue
      js_path = os.path.abspath(js_path)
      self.exec_eng(js_path)

  def gen_code(self, printer, model):
    stack = []
    ins_cnt = 0
    (seed_name,
     root, model_input) = self.prepare_seed(model)
    frag, hidden, parent_idx, frag_type = model_input

    while parent_idx != None:
      # Check max insertion condition
      if ins_cnt >= self._max_ins:
        return None
      else:
        ins_cnt += 1

      frag = data2tensor(frag)
      valid_type = frag_type
      parent_frag = self.idx2frag(parent_idx)
      parent_type = get_node_type(parent_frag)
      if valid_type == parent_type:
        if random.random() < 0.1:
          parent_idx, frag_type = self.expand_ast(parent_frag,
                                                    stack, root)
          frag = [parent_idx]
          continue
      parent_idx, frag_type = self.info2tensor(parent_idx,
                                               frag_type)
      outputs, hidden = model.run(frag, hidden,
                                  parent_idx, frag_type)

      _, cand_tensor = torch.topk(outputs[0][0],
                                  self._top_k)
      cand_list = cand_tensor.data.tolist()

      (found,
       frag,
       parent_idx, frag_type) = self.append_frag(cand_list,
                                                 valid_type,
                                                 root,
                                                 stack)
      if not found:
        msg = 'Failed to select valid frag at %d' % ins_cnt
        print_msg(msg, 'WARN')
        return None

    harness_list = self._harness.get_list(seed_name)
    self.resolve_errors(root, harness_list)

    root = self.postprocess(root, harness_list)
    js_path = printer.ast2code(root)
    return js_path

  def idx2frag(self, frag_idx):
    frag = self._frag_list[frag_idx]
    frag = deepcopy(frag)
    return frag

  def info2tensor(self, parent_idx, frag_type):
    parent_idx = [parent_idx]
    parent_idx = data2tensor(parent_idx)
    frag_type = [self._type_dict[frag_type]]
    frag_type = data2tensor(frag_type,
                            tensor_type="Float")
    return parent_idx, frag_type

  def log_cov(self):
    for cov in self._cov_set:
      line = str.encode(cov + "\n")
      self._cov_log.write(line)

  def postprocess(self, root, harness_list):
    # Insert Load
    body = [get_define_node(self._seed_dir)]

    for jspath in harness_list:
      load_node = get_load_node(jspath)
      if load_node not in body:
        body.append(load_node)

    body.append(root)
    root = {
      'type': 'Program',
      'body': body,
      'sourceType': 'script'
    }
    return root

  def prepare_seed(self, model):
    # Prepare AST
    seed_name, frag_seq = self.select_seed()
    (root,
     pre_seq,
     parent_idx,
     frag_type) = self.build_seed_tree(seed_name, frag_seq)

    # Prepare input for the model
    frag = [pre_seq[-1]]
    pre_seq = pre_seq[:-1]
    model_input = data2tensor(pre_seq)
    hidden = model.run(model_input)
    model_input = (frag, hidden, parent_idx, frag_type)
    seed_name = trim_seed_name(seed_name)
    return seed_name, root, model_input

  def push(self, stack, node):
    parent_idx = self.frag2idx(node)
    node_type = get_node_type(node)
    for key in reversed(PROP_DICT[node_type]):
      if key not in node: continue
      child = node[key]

      if (type(child) == dict and
          is_pruned(child)):
        info = (parent_idx, get_node_type(child))
        stack.append(info)
      elif type(child) == list:
        for _child in reversed(child):
          if _child != None and is_pruned(_child):
            info = (parent_idx, get_node_type(_child))
            stack.append(info)

  def resolve_errors(self, root, harness_list):
    try:
      # ID Resolve
      symbols = hoisting(root, ([],[]), True)
      resolve_id(root, None, symbols, True,
                 cand=[], hlist=harness_list)
    except ResolveBug as error:
      msg = 'Resolve Failed: {}'.format(error)
      print_msg(msg, 'WARN')

  def select_seed(self):
    seed_list = list(self._seed_dict.keys())
    frag_len = -1
    while frag_len < 3:
      seed_name = random.choice(seed_list)
      frag_seq, _ = self._seed_dict[seed_name]
      frag_len = len(frag_seq)
    return seed_name, frag_seq

  def traverse(self, node, frag_seq, stack):
    node_type = get_node_type(node)
    if node_type not in TERM_TYPE:
      parent_idx = self.frag2idx(node)
    else:
      return

    for key in PROP_DICT[node_type]:
      if key not in node: continue
      child = node[key]

      # If it has a single child
      if is_single_node(child):
        if is_pruned(child):
          frag_idx = frag_seq.pop(0)
          if frag_idx == -1:
            if stack != None:
              frag_info = (parent_idx,
                           get_node_type(child))
              stack.append(frag_info)
            continue
          frag = self.idx2frag(frag_idx)
          node[key] = frag
        self.traverse(node[key], frag_seq, stack)
      # If it has multiple children
      elif is_node_list(child):
        for idx, _child in enumerate(child):
          if _child == None:
            continue
          elif is_pruned(_child):
            frag_idx = frag_seq.pop(0)
            if frag_idx == -1:
              if stack != None:
                frag_info = (parent_idx,
                             get_node_type(_child))
                stack.append(frag_info)
              continue
            frag = self.idx2frag(frag_idx)
            child[idx] = frag
          self.traverse(child[idx], frag_seq, stack)

pass_exec_count_shared, total_exec_count_shared = None, None

def fuzz(conf):
  global pass_exec_count_shared, total_exec_count_shared
  set_start_method('spawn')
  #p = Pool(conf.num_proc, init_worker)
  pass_exec_count_shared = Value("i", 0)
  total_exec_count_shared = Value("i", 0)
  p = Pool(conf.num_proc, init, initargs=(pass_exec_count_shared, total_exec_count_shared,))
  #pool_map(p, run, range(conf.num_proc), conf=conf)
  try:
    func = partial(run, conf=conf)
    return p.map(func, range(conf.num_proc))
  except KeyboardInterrupt:
    print_msg('Terminating workers ...', 'INFO')
    final_cov = set()  
    for i in range(conf.num_proc):
      cov_path = [conf.bug_dir, 'proc.' + str(i), 'cov.csv']
      with open(os.path.join(*cov_path), "r") as f:
        final_cov |= set(f.readlines())
    with open("/home/shu/master-research/data/seed_coverage.txt", "r") as f:
      seed_cov = set(f.readlines())
    with open("/home/shu/master-research/data/log_" + datetime.now().strftime("%Y%m%d%H%M%S") + ".txt", "w") as f:
      f.write("Pass:" + str(pass_exec_count_shared.value) + "\n")
      f.write("Total:" + str(total_exec_count_shared.value) + "\n")
      f.write("Pass rate:" + str(pass_exec_count_shared.value / total_exec_count_shared.value) + "\n")
      f.write("Coverage:" + str(len(final_cov)) + "\n")
      f.write("Coverage diff:" + str(len(final_cov - seed_cov)) + "\n")
    p.terminate()
    p.join()
    print_msg('Killed processes', 'INFO')
    os.killpg(os.getpid(), signal.SIGKILL)

def init(pass_exec_count, total_exec_count):
  global pass_exec_count_shared, total_exec_count_shared
  pass_exec_count_shared = pass_exec_count
  total_exec_count_shared = total_exec_count
  signal.signal(signal.SIGINT, signal.SIG_IGN)

def is_pruned(node):
  keys = node.keys()
  return (len(keys) == 1 and
          'type' in keys and
          get_node_type(node) not in TERM_TYPE)

def load_data(conf):
  data_path = os.path.join(conf.data_dir,
                           'data.p')
  seed_data_path = os.path.join(conf.data_dir,
                                'seed.p')

  seed = load_pickle(seed_data_path)
  data = load_pickle(data_path)
  return seed, data

def load_model(model_path):
  model = torch.load(model_path)
  model.cuda()
  model.eval()
  return model

def run(proc_idx, conf):
  fuzzer = Fuzzer(proc_idx, conf)
  fuzzer.fuzz()
