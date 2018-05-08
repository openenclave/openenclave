Libmbed tests
=============

This directory run ARM Mbedtls tests in an enclave enviornment. It does
this by repeatedly building and running the enclave located under the 'enc' 
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

## LIBCIO 
    A Wrapper library implementation for the FILE I/O operations. Its a supportive library for the enclave
    applications such that any file operation comes, it can perform the same on host side and return to enclave.
    This library is a developed completly beased on OCALL implementation  
