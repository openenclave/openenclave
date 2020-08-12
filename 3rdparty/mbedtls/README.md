mbedTLS:
========

This directory contains the **mbedTLS** crypto library for enclaves.

The `./mbedtls` subdirectory is the https://github.com/ARMmbed/mbedtls
repo LTS mbedtls-2.16 branch, included as a git submodule.

The enclave version of mbedTLS builds the cloned sources with the following
changes:

- It uses a custom, scoped-down `config.h` defined in this folder.

- It compiles in `mbedtls_hardware_poll.c` extension to provide the custom
  entropy implementation mbedTLS libraries to avoid a circular dependency
  with the Open Enclave core runtime.

- It cherry-picks mbedtls patches from the development branch to the LTS
  branch:

  - de7e036: Merge pull request #3489 from CodeMonkeyLeet/mbedtls-2.16_backport_3464
  - dfd5172: Merge pull request #3488 from CodeMonkeyLeet/mbedtls-2.16_backport_2632
