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

Note that test_exception.cc requires std::uncaught_exceptions(), which is not
supported by gcc version 5 that Open Enclave targets as the standard compiler
version. With compilers that support this, such as Clang 3.8, or gcc version 6
and above, the comparison version of the test can be compiled directly against
system dependent libraries instead of **libcxxrt and standard library
dependencies**.


To test, test.cc on Windows, perform following steps in given order...
===============================================================================
1. Compile libcxxrt on WSL first, if openenclave folder is cloned in path
	"${env.WSL_ROOTFS}/home/username/openenclave" then this will generate
	libcxxrt log files in path
	"${env.WSL_ROOTFS}/home/username/openenclave/build/tests/libcxxrt".

2. Open openenclave project in Visual Studio and select Linux-Debug
	configuration and build libcxxrt and it will generate second set
	of libcxx log file on path
	"${env.WSL_ROOTFS}/var/tmp/build/${workspaceHash}/build/Linux-Debug/tests/libcxxrt".

3. Select x64-Debug-tests configuration and build and run libcxxrt tests...

	3.1. This project will check if log files using WSL build is generated or
	not and for that libcxxrt log files path on WSL machine should be passed
	as cmake arguments in CMakeSettngs.js file, for ex.
	"-DLINUX_LIBCXXRT_LOG_DIR=${env.WSL_ROOTFS}/home/username/openenclave/build/tests/libcxxrt".

	3.2 After 3.1 is successful, Direct WSL build libcxxrt log files will be
	copied to windows project binary folder and then will be compared with
	log files generated from Visual studio Linux-Debug build, if both log files
	are equal then test will be marked as passed, otherwise test will be
	marked as failed.

Note : Above mechanism will compare following three log files.
	1. exp_test_exception_output.log
	2. exp_test_guard_output.log
	3. exp_test_typeinfo_output.log

	test_foreign_exceptions.cc is tested same as Linux.
