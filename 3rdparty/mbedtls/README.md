mbedTLS:
========

This directory contains the **mbedTLS** crypto library for enclaves.
The `./mbedtls` subdirectory contains a clone of the sources downloaded
from https://tls.mbed.org/download-archive.

The version of mbedTLS currently in use is reflected in `update.make`.

The enclave version of mbedTLS builds the cloned sources with the following
changes:

- It uses a custom, scoped-down `config.h` defined in this folder.

- It compiles in `mbedtls_hardware_poll.c` extension to provide the custom
  entropy implementation mbedTLS libraries to avoid a circular dependency
  with the Open Enclave core runtime.

- It patches `mbedtls/library/x509write_crt.c` with
  `0001-Patch-x509write_crt.c-for-attestedTLS.patch` to add support for writing
  certificates that support using TLS with enclave attestation for auth.
