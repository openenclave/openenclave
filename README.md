Open Enclave SDK
================

Introduction
------------

Open Enclave is an SDK for building enclave applications in C and C++. An
enclave application partitions itself into an untrusted component (called the
host) and a trusted component (called the enclave). An enclave is a secure
container whose memory is protected from entities outside the enclave. These
protections allow enclaves to perform secure computations with assurances that
secrets will not be compromised.

The current implementation of Open Enclave is built on the Intel Software Guard
Extensions (SGX), although Open Enclave may support other memory protection
architectures in the future, such as Microsoft Virtualization Based Security
(VBS).

Design Overview
-------------

- [Open Enclave Design Overview](doc/DesignOverview.pdf)


Getting Started
-------------

1. Determine the SGX configuration type of your development system

   The SDK setup/build process depends on the trarget configuration. 
   There are three supported configurations. 
    - SGX 1: This is the orginal Intel SGX hardware platform
    - SGX 1+FLC: SGX with Flexible Launch Control support
    - Software SGX Simulation: supported by a pure software SGX emulator
    
    An oesgx utility (**add a link to linux version of this tool here**) could be use to determine thr SGX support on your target system.  

2. Build and Run
   - [Software SGX Simulation](doc/SwSimulationGettingStarted.md)
   - [SGX 1](doc/SGX1GettingStarted.md)
   - [SGX 1  + FLC](doc/SGX1FLCGettingStarted.md)

Open Enclave SDK Function Reference
-------------------------------
- [Open Enclave Function Reference](doc/refman/md/index.md)

Contributing
------------
See [Contributing to Open Enclave](doc/Contributing.md) for information about
contributing to the Open Enclave project.

See the [Development Guide](doc/DevelopmentGuide.md) for details about developing
code in this repo, such as coding style and development processes.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.


Licensed under the MIT License.
-------
