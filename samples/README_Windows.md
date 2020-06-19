# Building Open Enclave SDK Samples on Windows

All the samples that come with the Open Enclave SDK installation share a similar directory structure and build instructions. This document describes how to setup, build, sign and run these samples.

## Common Sample information

### How Sample source code directories were structured

Open Enclave SDK helps developers build enclave applications. An enclave application is partitioned into an untrusted component (called a host) and a trusted component (called an enclave).

An enclave is a secure container whose memory (text and data) is protected from access by outside entities, including the host, privileged users, and even the hardware. All functionality that needs to be run in a Trusted Execution Environment (TEE) should be compiled into the enclave binary. The enclave may run in an untrusted environment with the expectation that secrets will not be compromised. On Windows and Linux, enclaves are ELF binaries.

A host is a normal user mode application that loads an enclave into its address space before starting interacting with an enclave.

![Sample components diagram](sampledirstructure.png)

All the samples that come with the Open Enclave SDK installation are all structured into two subdirectories (one for enclave and one for host) accordingly.

| Files/dir        |  contents                                   |
|:-----------------|---------------------------------------------|
| enclave        | Files needed for building the sample enclave  |
| host           | Files needed for building the host            |

### Prepare samples

Building a sample will write intermediate and output files into the sample directory. If you would like to use a separate working directory for building samples, you can copy the samples to your working directory first. For example, if the SDK was installed to C:\openenclave:

```cmd
xcopy C:\openenclave\share\openenclave\samples C:\mysample
```

### How to build and run samples

1. [x64 Native Tools Command Prompt for VS2017 or 2019](
https://docs.microsoft.com/en-us/dotnet/framework/tools/developer-command-prompt-for-vs)

2. Set `CMAKE_PREFIX_PATH` to the cmake directory in the Open Enclave SDK installation.

As an example, if the Open Enclave SDK is installed to `C:\openenclave`, then you would set `CMAKE_PREFIX_PATH` as shown below

```cmd
set CMAKE_PREFIX_PATH=C:\openenclave\lib\openenclave\cmake
```

3. To build a sample using CMake, change directory to your target sample directory and execute the following commands:

```cmd
mkdir build
cd build
cmake .. -G Ninja -DNUGET_PACKAGE_PATH=C:\oe_prereqs
ninja
```

4. To run the sample, use below:

```cmd
ninja run
```

5. To run the sample in simulation mode, use below:

```cmd
ninja simulate
```

#### Build and Run samples with LVI mitigation

Refer to [here](helloworld#build-and-run-with-lvi-mitigation) for more details.

## Samples

The following samples demonstrate how to develop enclave applications using OE APIs. It's recommended to go through the following samples in the order listed.

#### [HelloWorld](helloworld/README.md)

- Minimum code needed for an OE app
- Help understand the basic components an OE application
- Demonstrate how to build, sign, and run an OE image
- Demonstrate how to optionally apply LVI mitigation to enclave code

#### [File-Encryptor](file-encryptor/README.md)

- Show how to encrypt and decrypt data inside an enclave
- Use AES mbedTLS API to perform encryption and decryption

#### [Data-Sealing](data-sealing/README.md)

- Introduce OE sealing and unsealing features 
- Demonstrate how to use OE sealing APIs
- Explore two supported seal polices
  - OE_SEAL_POLICY_UNIQUE
  - OE_SEAL_POLICY_PRODUCT

#### [Remote Attestation](remote_attestation/README.md)

- Explain how OE attestation works
- Demonstrate an implementation of remote attestation between two enclaves running on different machines

#### [Local Attestation](local_attestation/README.md)

- Explain the concept of OE local attestation
- Demonstrate an implementation of local attestation between two enclaves on the same VM

#### [Attested TLS](attested_tls/README.md)

- Explain what an Attested TLS channel is
- Demonstrate an implementation for how to establish an Attested TLS channel
  - between two enclaves
  - between one non-enclave client and an enclave

#### [Switchless Calls](switchless/README.md)

- Explain the concept of switchless calls
- Identify cases where switchless calls are appropriate
- Demonstrate how to mark a function as `transition_using_threads` in EDL
- Demonstrate how to configure an enclave to enable switchless calls originated within it
- Recommend the number of host worker threads required for switchless calls in practice
- Demonstrate how to enable switchless calls in an enclave application

#### [Host-side Enclave Verification](host_verify/README.md)

- Explain the concept of host-side enclave verification
- Demonstrate attestation of a remote SGX enclave from outside an enclave

#### [Pluggable Allocators](pluggable_allocator/README.md)

- Demonstrate how to replace the default memory allocator by plugging in a custom allocator
  that performs better in multi-threaded enclaves.
- Provide overview of how to make an enclave-compatible allocator pluggable.
