mbedTLS tests
=============

This directory contains mbedTLS tests adapted to run in an enclave environment.

For each mbedTLS test suite supported in the OE SDK, an enclave version of that
test suite is built under the 'enc' subfolder and a ctest added for it.

The mbedTLS test suites are partitioned into three files:

- **tests.supported:** Tests that should succeed in an enclave and are actively used for regression testing.
- **tests.unsupported:** Tests that are not run because they are not supported in an enclave. These tests
   are classified as unsupported because either:
  - The functionality under test is not supported in an enclave.
  - The test is not feasible or appropriate to run inside an enclave.
- **tests.broken:** Tests that fail to run in an enclave, but are under investigation as to whether they
   can or should be fixed to run inside an enclave. These tests are also not run by default.
    - If a test is fixed, it should be moved to tests.supported.
    - If a test is determined to be infeasible or inappropriate to run in an enclave,
      it should be moved to tests.unsupported.

The sum of all the tests in these three files should match the test suites added by the upstream
3rdparty/mbedtls/mbedtls/tests/CMakeLists.txt file, with the exception of the additional _selftest_.

The selftest entry in tests.supported is not one of the regular mbedTLS test suites; it is instead
an adaptation of the selftest executable that is part of the mbedTLS test programs under
3rdparty/mbedtls/mbedtls/programs/tests/CMakeLists.txt. It is included in the tests.supported file to
provide a consistent view of all tests we support running in the enclave but is handled separately in
the CMakeLists.txt for this directory.

Note that the test host contains syscall hook implementations for a few file I/O operations
needed by some mbedTLS tests. These are just simple OCall wrappers with no security guarantees
and are only intended for mbedTLS test use.
