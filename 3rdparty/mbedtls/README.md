mbedTLS:
========

This directory contains the **mbedTLS** crypto library for enclaves.

The `./mbedtls` subdirectory points at the git submodule inclusion of
https://github.com/openenclave/openenclave-mbedtls at the head of the
openenclave-mbedtls-2.16 branch. This branch is identical to the mbedTLS
2.16 LTS branch, with additional patches in the process of being upstreamed.

The enclave version of mbedTLS builds the cloned sources with the following
changes:

- It uses a custom, scoped-down `config.h` defined in this folder.

- It compiles in `mbedtls_hardware_poll.c` extension to provide the custom
  entropy implementation mbedTLS libraries to avoid a circular dependency
  with the Open Enclave core runtime.
