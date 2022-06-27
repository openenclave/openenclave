Libcxxrt tests
=============

This directory run libcxxrt tests in an enclave enviornment. It does
this by repeatedly building and running the enclave located under the 'enc'
directory for each unit test found in tests.supported.

The unit tests are partitioned into three files:

* tests.supported -- unit tests that work
* tests.unsupported -- unit tests that are not supported

To run all the tests, type the following command:

```
# make tests
```

As tests are fixed, they should be moved from tests.broken to tests.supported.

As tests are determined to be unsupportable, they should be moved from
tests.broken to tests.unsupported.

Note
====

libcxxrt basically contains two tests:

  1. test_foreign_exceptions.cc

In case of test_foreign_exception, it is tested using the return value from
the main() function and hence conclude whether test is success or failure.

  2. test.cc (contains test_guard.cc, test_typeinfo.cc and test_exception.cc)

In case of test.cpp, the main(), which is of void type, will generate a
sequence of test logs regarding test_guard, test_typeinfo and test_exception.

Test is compiled in two different ways, one using **libcxxrt** and the other
using standard system depended libraries (i.e., it will use **libsupcxx** ABI
library instead of libcxxrt). It then generates a log file for each version of
the test and compares them with each other. The test is marked as passing only
if both log files are identical.

Since these tests are dependent comparing test-generated logs, test files such
as enc.cpp and host.cpp must not print any messages to stdout, as these messages
will not match the comparison log that does not include these additional messages.

For the enclave versions of these tests, the following additional modifications
were needed:

* Separated test_guard.cpp, test_typeinfo.cpp and test_exception.cpp from
test.cpp so that each test can be executed individually using the test
configuration files tests.supported/unsupported.

* Each test (test_guard.cc, test_typeinfo.cc and test_exception.cc) is compiled
against **libcxxrt** in both cases. Instead of the test comparison being
between the use of **libcxxrt** and **libsupcxx** as in the normal version,
the enclave version compares the log of the test built against **libcxxrt
using OE dependencies** (e.g. OE version of libunwind) with the log of the
one built against **libcxxrt and standard library dependencies**.


To test, test.cc on Windows, perform following steps in given order...
==========================================================================

Select Linux-Debug configuration and build libcxxrt logs.

Select x64-Debug-tests configuration and build and run libcxxrt tests...

2.1. Libcxxrt Signed .so files will be copied to windows project binary folder .

2.2 After 2.1 is successful, Linux Libcxxrt log files will be copied to windows
project binary folder.

2.3 Libcxxrt log files will be generated using run.bat file in windows project binary folder.

2.4 Linux and Windows Logs will be compared to pass the test.

Note that test_exception.cc requires std::uncaught_exceptions(), which requires
cpp standard **stdc++17** (or above) with compiler version **Clang 3.8** (or above).
