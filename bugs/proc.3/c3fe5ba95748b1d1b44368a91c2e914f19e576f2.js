if (typeof load == 'undefined')
    load = function (js_path) {
        WScript.LoadScriptFile('/home/spqr/js-test-suite/testsuite/'.concat(js_path));
    };
load('8b38e12cab5de21ec5393724c0d9b7dd.js');
var v0 = new Array(2000000);
var v1 = 0;
try {
    while (true) {
        v0[v0.length] = new Object();
    }
} catch (e) {
}
for (var v22 = 0; v1 < 10; v1++) {
    WScript.Echo(v1);
    CollectGarbage();
}