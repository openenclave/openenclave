libcxx tests
============

This directory runs each LLVM libcxx unit test from within an enclave. It does
this by repeatedly building and runing the enclave located under the 'enc' 
directory for each unit test found in tests.supported.

The unit tests are partitioned into three files:

* tests.supported -- unit tests that work
* tests.supported.cxx17 -- unit tests of C++17 features that work (compiled with std=c++17)
* tests.supported.default -- subset of working tests ran by daily build
* tests.broken -- unit tests that are broken
* tests.unsupported -- unit tests that are not supported

To run all the tests, type the following command:

```
# make tests
```

As tests are fixed, they should be moved from tests.broken to tests.supported.

As tests are determined to be unsupportable, they should be moved from
tests.broken to tests.unsupported.
