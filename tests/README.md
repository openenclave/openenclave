tests
=====

# Overview:

This directory contains all the unit tests for Open Enclave. Type the following
commands to build and run the tests from the corresponding CMake output folder.

```
# make
# ctest
```

This builds and runs all the tests except for libcxx, which is very slow to
build and run.

# Testing on Windows

Refer to [Getting Started on Windows](../doc/GettingStarted.Windows.md) for
instructions on testing Linux-built enclaves with Windows-built host apps.
