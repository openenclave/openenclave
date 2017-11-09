tests
=====

# Overview:

This directory contains all the unit tests for OpenEnclave, including the unit
tests for third-party components (such as MUSL-libc and and LLVM-libcxx).

The tests are built from the top-level directory and can be run by typing
'make tests' from the top-level or from this directory.

The 'make tests' command runs all tests except for libcxx and libc (which
take a very long time to build and to run). To build and run all tests use
these commands.

```
# make ALL=1
# make tests ALL=1
```

Alternatively, these tests can be built and run from their respective
directories (libc and libcxx).

# wraptest and runtest

Some tests use the wraptest and runtest utilities. See the README in the
respective directories for details.

