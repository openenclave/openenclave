enclave
=======

This directory contains the sources for the oeenclave library. The library includes
the `oe_call_link_enclave` function along with the `_start` function,
which is the default entry point for the enclave image
(see [sgx/start.S](sgx/start.S) and [optee/start.S](optee/start.S)).
Doing so ensures that the symbols referenced by the `oe_call_link_enclave`
(see `oe_link_enclave` in [link.c](link.c)) get linked before other
libraries (e.g., oecore). Such linker behavior allows us to
support API plugin model (e.g., pluggable allocators).

*Note*: The `oeenclave` is required to be the first library for an enclave to link against.

The directory also includes three sub-directories, including

- [attestation/](attestation/)
  - The implementation of the oeattestation library.
- [core](core/)
  - The implementation of the oecore library.
- [crypto](crypto/)
  - The implementation of the oecrypto* library.
