enclave
=======

This directory contains the sources for the oeenclave library, which implements
the enclave extras. The main parts include:

- Remote attestation support
  - Certificate operations ([tls_cert.c](tls_cert.c))
  - Asymmetric key operations ([asym_keys.c](asym_keys.c))
  - Platform-specific implementations ([sgx/](sgx/) and [optee/](optee/))
