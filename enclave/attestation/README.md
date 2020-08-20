attestation
===========

This directory contains the sources for the oeattestation library, which depends on
the oecrypto* and oelibc. The main parts include:

- Remote attestation support
  - Certificate operations ([tls_cert.c](tls_cert.c))
  - Asymmetric key operations ([asym_keys.c](asym_keys.c))
  - Attestation plugin([attest_plugin.c](attest_plugin.c))
  - Platform-specific implementations ([sgx/](sgx/) and [optee/](optee/))
