Libunwind tests
=============

This directory runs the libunwind tests in an enclave enviornment. It does
this by repeatedly building and running the enclave located under the 'enc' 
directory for each unit test found in tests.supported.

The unit tests are partitioned into three files:

* tests.all
* tests.supported -- unit tests that work
* tests.unsupported -- unit tests that are not supported

To run all the tests, type the following command:

```
# make tests
```

Note
====
libunwind basically contains 33 tests which are listed in the tests.all file.
Out of these 33 tests, 11 tests can be compiled and run properly and are listed
in the test.supported file. The remaining 22 tests were moved to the
test.unsupported file.

All the tests in test.supported can be compiled and run properly in debug 
mode("-O2"). In release mode("-O3"), a couple of tests (Gtest-exc and Ltest-exc)
were failing. Those tests were also failing in system dependent side when
compiled with -O3. By adding GCC flag "fno-inline-function" with -O3 flag
("-O3 -fno-inline-function") both system dependent tests as well as enclave 
tests were able to run sucessfully in release mode.

The tests listed in tests.unsupported file uses the features that enclave 
don't support like signals, pthreads, timers, dynamic loading etc.

Out of the 22 unsupproted tests, 4 of them are bash scripts. They are

* run-coredump-unwind
* run-check-namespace
* run-ptrace-mapper
* run-ptrace-misc

The detailed list of the unsupported tests with their features that are not
supported are given below :

SL.No | Tests_Name  | Compile? | Run? | Comments |
:---:|:---:|:---:|:---:|:---:|
1  | Gtest-bt | No | No | undefined reference to 'kill', 'sigaltstack', 'sigaction', 'signal' |
2  | Gtest-concurrent   | No |  No | undefined reference to 'signal', 'pthread_kill', 'pthread_attr_init', 'pthread_attr_setstacksize' |
3  | Gtest-dyn1 | No | No | undefined reference to 'mprotect', `signal' |
4  | Gtest-resume-sig | No | No | undefined reference to 'sigemptyset', 'sigaddset', 'sigprocmask', 'signal', 'kill', 'sigaction' |
5  | Gtest-resume-sig-rt| No | No | undefined reference to 'sigemptyset', 'sigaddset', 'sigprocmask', 'signal', 'kill', 'sigaction' | 
6  | Gtest-trace | No | No | undefined reference to 'kill', 'sigaltstack', 'sigaction', 'signal' |
7  | Ltest-bt | No |  No | undefined reference to 'kill', 'sigaltstack', 'sigaction', 'signal' |
8  | Ltest-concurrent | No | No |undefined reference to 'signal', 'pthread_kill', 'pthread_attr_init', 'pthread_attr_setstacksize' |
9  | Ltest-dyn1 | No | No | undefined reference to 'mprotect', 'signal' |
10 | Ltest-nocalloc | No | No | undefined reference to `dlsym' |
11 | Ltest-nomalloc | No | No | undefined reference to `dlsym' |
12 | Lrs-race | Yes | No | test calls pthread_create() and gets aborted |
13 | Ltest-resume-sig | No | No | undefined reference to 'sigemptyset', 'sigaddset', 'sigprocmask', 'signal', 'kill', 'sigaction' |
14 | Ltest-resume-sig-rt | No | No |undefined reference to 'sigemptyset', 'sigaddset', 'sigprocmask', 'signal', 'kill', 'sigaction' |
15 | Ltest-trace | No | No | undefined reference to 'kill', 'sigaltstack', 'sigaction', 'signal' |
16 | run-coredump-unwind | No | No | execinfo.h is not supported |
17 | run-check-namespace | No | No | this test will check whether some specific symbols are there in the generated libraries or not |
18 | run-ptrace-mapper | No | No | depends on test-ptrace |
19 | run-ptrace-misc | No | No | depends on test-ptrace |
20 | test-async-sig | No | No | undefined reference to 'setitimer', 'sigaction' |
21 | test-ptrace | No | No | undefined reference to 'kill', 'fork', 'open', 'dup2', 'ptrace', 'execve', 'wait4' |
22 | test-setjmp | No | No | undefined reference to 'sigsetjmp', 'sigaddset', 'sigprocmask', 'siglongjmp' 'sigemptyset', 'kill', 'sigaction' |

run-coredump-unwind does not have support for execinfo.h which declares the functions backtrace, backtrace_symbols, backtrace_symbols_fd.
Currently enc/CMakeLists.txt have  support  for the tests in tests.supported.
To compile any of the test from test.unsupported you have to add the corresponding support libraries in the enc/CMakeLists.txt.
