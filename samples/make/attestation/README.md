samples/make/attestation
============

This directory contains a sample that demonstrates remote attestation and use of mbedtls within the enclave.

The host creates two enclaves. The enclaves first exchange their public encryption keys. Then they exchange encrypted data.

## Build
```
$ make OPENENCLAVE_CONFIG=/usr/local/share/openenclave/config.mak     
```

## Run
```
$ make OPENENCLAVE_CONFIG=/usr/local/share/openenclave/config.mak run
```

## Description

### ./
* args.h: Defines arguments types of ECALL functions.

### ./enc/
* attestation.h/.cpp: Demonstrates use of **OE_GetReport** to generate a report and **OE_VerifyReport** to attest a report. The reportData field of a report is used to store the hash of data accompanying a report.
* crypto.h/.cpp: Demonstrates use of **mbedtls** for cryptography within the enclave.
* ecalls.h/.cpp: Demonstrates patterns of writing enclave **ECALL** functions that are called by the host. Demonstrates how to safely copy input and output parameters across the host/enclave memory boundary.
* init.cpp: Demonstrates how to initialize various modules within the enclave.
* log.h: Demonstrates use of **OE_HostPrintf** for logging.
* Makefile: Demonstrates building enclave's that uses mbedtls, and C++ standard library.

### ./host/
* ecalls.h/.cpp: Demonstrates writing wrappers for **ECALL** functions. Demonstrates how to assemble the arguments for ECALLs and how to test result of an ECALL.
* host.cpp: Demonstrates how to create, use and terminate enclaves.
* Makefile: Demonstrates building enclave hosts.
