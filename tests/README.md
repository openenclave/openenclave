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
directory and run ctest from there, such as:

```
build/tests/echo$ make
```


This builds and runs all the tests except for libcxx, which is very slow to
build and run. To enable, set the ENABLE_LIBCXX_TESTS cmake variable, such as

```
build$ cmake .. -DENABLE_LIBCXX_TESTS=1
build$ make
build$ ctest

```

# Test mechanics

This sub-tree is build with the "NDEBUG" C preprocessor macro undefined,
even for debug builds. This allows assert() to be used as a simple check,
and is the general paradigm in all tests.

Some tests can only be run in certain environments and fail in others. It is
recommended for such tests to check the environment, and abort the test
signalling a "did not run" state to ctest (rather than failing). To signal
"did not run", such tests should return with an exit code of 2. ctest
evaluates this specifically.

# Testing on Windows

Refer to [Getting Started on Windows](../doc/GettingStarted.Windows.md) for
instructions on testing Linux-built enclaves with Windows-built host apps.


