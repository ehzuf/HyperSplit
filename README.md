# HyperSplit

build/:
 store the built staff
code/:
 source code
test/rules/:
 test rules from classbench
test/traces/:
 traces corresponding to the above rules


``` Bash
$ make clean
$ make
$ ./build/pc_algo -r test/rules/fw1_10K -t test/traces/fw1_10K_trace
```
