import triton
import pintool
import pickle
import copy
import os

FILE_PATH = "../../data/"
Triton = pintool.getTritonContext()
blockList = set()
controlFlow = False

def updateBlockCoverage(inst):
  global blockList
  global controlFlow
  if controlFlow:
    blockList.add(hex(inst.getAddress()))
    controlFlow = False
  if inst.isControlFlow():
    controlFlow = True
  with open(FILE_PATH + "blocklist.pkl", "wb") as data:
    print(blockList)
    pickle.dump(blockList, data)

def main():
  global blockList
  if os.path.exists(FILE_PATH + "blocklist.pkl"):
    with open(FILE_PATH + "blocklist.pkl", "rb") as data:
      blockList = pickle.load(data)
  
  Triton.setArchitecture(triton.ARCH.X86_64)
  Triton.enableMode(triton.MODE.ALIGNED_MEMORY, True)
  pintool.startAnalysisFromSymbol("main")
  pintool.insertCall(updateBlockCoverage, pintool.INSERT_POINT.BEFORE)
  pintool.runProgram()

if __name__ == "__main__":
  main()