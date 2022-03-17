mbedTLS:
========

This directory contains the **mbedTLS** crypto library for enclaves.

The `./mbedtls` subdirectory points at the git submodule inclusion of
https://github.com/openenclave/openenclave-mbedtls at the head of the
openenclave-mbedtls-2.16 branch. This branch is identical to the mbedTLS
2.28 LTS branch, with additional patches in the process of being upstreamed.

The enclave version of mbedTLS builds the cloned sources with the following
changes:

- It uses a custom, scoped-down `config.h` defined in this folder.

- It compiles in `mbedtls_hardware_poll.c` extension to provide the custom
  entropy implementation mbedTLS libraries to avoid a circular dependency
  with the Open Enclave core runtime.

- It fixes dependencies in the test_suite_ssl.data and test_suite_ssl.function so
  that some of the ssl tests will be correctly skipped when the corresponding configurations are disables (non-default, OE's selections).
