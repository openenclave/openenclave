samples/make/attestation
============

This directory contains a sample that demonstrates remote attestation and use of mbedtls within the enclave.

The host application creates a pair of enclaves that exchange their public keys using attestation, then exchange data encrypted to those keys with each other.

## Build
```
$ make OPENENCLAVE_CONFIG=<openenclave install dir>/share/openenclave/config.mak     
```

## Run
```
$ make OPENENCLAVE_CONFIG=<openenclave install dir>/share/openenclave/config.mak run
```

## Description

### ./
* args.h: Defines arguments types of ECALL functions.

### ./enc/
* attestation.h/.cpp: Demonstrates use of **oe_get_report** to generate a report and **oe_verify_report** to attest a report. The reportData field of a report is used to store the hash of data accompanying a report.
* crypto.h/.cpp: Demonstrates use of **mbedtls** for cryptography within the enclave.
* ecalls.h/.cpp: Demonstrates patterns of writing enclave **ECALL** functions that are called by the host. Demonstrates how to safely copy input and output parameters across the host/enclave memory boundary.
* init.cpp: Demonstrates how to initialize various modules within the enclave.
* log.h: Uses printf for logging within the enclave.
* Makefile: Demonstrates building enclaves that use mbedtls, and C++ standard library.

### ./host/
* ecalls.h/.cpp: Demonstrates writing wrappers for **ECALL** functions. Demonstrates how to assemble the arguments for ECALLs and how to test result of an ECALL.
* host.cpp: Demonstrates how to create, use and terminate enclaves.
* Makefile: Demonstrates building enclave hosts.
