Libmbed tests
=============

This directory runs the mbed TLS tests in an enclave enviornment. It does
this by repeatedly building and running the enclave located under the 'enc' 
directory for each unit test found in tests.supported.

The unit tests are partitioned into three files:

* tests.supported -- unit tests that work
* tests.broken -- unit tests that are broken
* tests.unsupported -- unit tests that are not supported

To run all the tests, type the **ctest** command:

As tests are fixed, they should be moved from tests.broken to tests.supported.
As tests are determined to be unsupportable, they should be moved from
tests.broken to tests.unsupported.
