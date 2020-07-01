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

- It backports mbedtls patches from the development branch to the LTS version
  OE currently uses:

  - Update `mbedtls/library/x509write_crt.c` with fixes from [#2632](
    https://github.com/ARMmbed/mbedtls/pull/2632) contained in
    `0001-Backport-2632-code-changes-to-2.16.patch`.

  - Update `mbedtls/library/x509write_csr.c` with fixes from [#3464](
    https://github.com/ARMmbed/mbedtls/pull/3464) contained in
    `0001-Avoid-stack-allocation-of-large-memory-buffers.patch`.
