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

test_exception.cc requires std::uncaught_exceptions() which is supported by 
clang 3.8 or gcc version 6 or above. Currently our enclave only support gcc 
version 5. So this test is moved to test.unsupported.
