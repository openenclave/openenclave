libcxxthrd tests
================

This directory runs each LLVM libcxxthrd unit test from within an enclave. It does
this by repeatedly building and runing the enclave located under the 'enc' 
directory for each unit test found in tests.supported.

The unit tests are partitioned into three files:

* tests.supported -- unit tests that work
* tests.broken -- unit tests that are broken
* tests.unsupported -- unit tests that are not supported

To run all the tests, type the following command:

```
# make tests
```

As tests are fixed, they should be moved from tests.broken to tests.supported.

As tests are determined to be unsupportable, they should be moved from
tests.broken to tests.unsupported.

Implementation details:
Since threads cannot be created or destroyed inside an enclave, the test implements hooks for 
pthread_create, pthread_join and pthread_detach using the register_hooks interface 
provided in the core for test use. Hence, there is additional timing or delay introduced
in the multi-threaded test environment while transitioning to the host using these hooks.

