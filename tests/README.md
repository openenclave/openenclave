tests
=====

# Overview:

This directory contains dedicated unit tests for Open Enclave. To run all
tests Open Enclave tests, type the following commands to build and run the
tests from the corresponding CMake output folder.

```
build$ make
build$ ctest
```

To run only specific tests, go to the corresponding subtree in the build
directory and run ctest from there. For example,

```
build/tests/echo$ make
```


This builds and runs all the tests. For libcxx a small subset is the default,
the complete one is very slow to build and run. To enable the full set,
set the ENABLE_FULL_LIBCXX_TESTS cmake variable as follows:

```
build$ cmake .. -DENABLE_FULL_LIBCXX_TESTS=1
build$ make
build$ ctest

```

# Test mechanics

OE_TEST() is used as a simple check, and is the general paradigm in all tests.

Some tests can only be run in certain environments and fail in others. It is
recommended for such tests to check the environment, and abort the test
signalling a "did not run" state to ctest (rather than failing). To signal
"did not run", such tests should return with an exit code of 2. ctest
evaluates this specifically.

# Testing on Windows [Work in progress]

Refer to [Getting Started on Windows](/docs/GettingStartedDocs/GettingStarted.Windows.md) for
instructions on testing Linux-built enclaves with Windows-built host apps.


