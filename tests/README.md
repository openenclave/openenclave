tests
=====

# Overview:

This directory contains all the unit tests for OpenEnclave. Type the following 
commands to build and run the tests.

```
# make
# make tests
```

This builds and runs all the tests except for libc and libcxx. These tests are
very slow and should be run from the directories with the same names.
