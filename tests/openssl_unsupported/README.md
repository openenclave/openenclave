Unsupported OpenSSL APIs/macros tests
==============================

This directory includes the tests of OpenSSL APIs/macros that are disabled by OE for
security concerns. Each test compiles an enclave that uses one of such APIs/macros
and expects the compilation to fail. Specifically, the test checks if the
build log contains a particular string that indicates the compilation fails
expectedly.
