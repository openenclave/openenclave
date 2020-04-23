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

The tests are currently ran with the following configurations.

| Compiler    | Environment          | Test set |
|-------------|----------------------|----------|
| gcc 5.4.0   | Ubuntu 16.04         | Full     |
| gcc 7.5.0   | Ubuntu 18.04         | Full     |
| gcc 8.3.1   | Red Hat 8            | Default  |
| clang 7.1.0 | Ubuntu 16.04 & 18.04 | Full     |
| clang 8.0.1 | Red Hat 8            | Default  |

*Note*: For compatibility, some test cases are disabled on certain versions of compilers via [CMakeLists.txt](CMakeLists.txt).

To run all the tests, type the following command:

```
# make tests
```

As tests are fixed, they should be moved from tests.broken to tests.supported.

As tests are determined to be unsupportable, they should be moved from
tests.broken to tests.unsupported.
