Open Enclave SDK
================

[![Bors enabled](https://bors.tech/images/badge_small.svg)](https://app.bors.tech/repositories/21855) [![Build Status](https://oe-jenkins.eastus.cloudapp.azure.com/buildStatus/icon?job=OpenEnclave-nightly_packages)](https://oe-jenkins.eastus.cloudapp.azure.com/job/OpenEnclave-nightly_packages/) [![Join the chat at https://gitter.im/openenclave/community](https://badges.gitter.im/openenclave/community.svg)](https://gitter.im/openenclave/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

Introduction
------------

Open Enclave (OE) is an SDK for building enclave applications in C and C++. An
enclave application partitions itself into two components:
1. An untrusted component (called the host) and
2. A trusted component (called the enclave).

An _enclave_ is a protected memory region that provides confidentiality for data
and code execution. It is an instance of a Trusted Execution Environment (TEE)
which is usually secured by hardware, for example,
[Intel Software Guard Extensions (SGX)](https://software.intel.com/en-us/sgx).

This SDK aims to generalize the development of enclave applications across TEEs
from different hardware vendors. The current implementation provides support for
Intel SGX as well as preview support for OP-TEE OS on ARM TrustZone. As an
open source project, this SDK also strives to provide a transparent solution
that is agnostic to specific vendors, service providers and choice of operating
systems.

Getting Started
---------------

### Intel SGX

If you would like to start developing apps with the preview Open Enclave SDK
release, start here for instructions to install and use the SDK package:

- [Ubuntu 18.04 with SGX hardware](docs/GettingStartedDocs/install_oe_sdk-Ubuntu_18.04.md)
- [Ubuntu 16.04 with SGX hardware](docs/GettingStartedDocs/install_oe_sdk-Ubuntu_16.04.md)
- [Ubuntu 18.04 or 16.04 in simulation mode](docs/GettingStartedDocs/install_oe_sdk-Simulation.md)
- Windows Release Package coming soon

If you would like to run Ubuntu 16.04 or Ubuntu 18.04 in a Hyper-V VM on SGX
capable hardware, see
[Setting up a Linux Hyper-V VM on Windows with SGX Support](docs/GettingStartedDocs/HyperVLinuxVMSetup.md).

### OP-TEE OS (ARM TrustZone)

The Open Enclave SDK provides preview support for the Open Portable TEE OS
(OP-TEE OS). OP-TEE is an operating system for TEE's that implement a
traditional kernel-mode and user-mode execution environment. It runs on
A-profile ARM systems that support ARM TrustZone. As a result, the Open Enclave
SDK can be leveraged to target these systems as well.

For an overview of the SDK's support for OP-TEE OS as well as links to getting
started guides, see
[Open Enclave SDK for OP-TEE OS](docs/GettingStartedDocs/OP-TEE/Introduction.md).

Contributing
------------

This project welcomes contributions and suggestions. All contributions to the Open Enclave SDK
must adhere to the terms of the [Developer Certificate of Origin (DCO)](https://developercertificate.org/).
For details, see [Contributing to Open Enclave](docs/Contributing.md).

This project follows a [Code of Conduct](docs/CodeOfConduct.md) adapted from the
[Contributor Covenant v1.4](https://www.contributor-covenant.org).

If you are interested in contributing directly to the codebase, please see the following
documentation:
- [Development Guide](docs/DevelopmentGuide.md)
- [Governance Model](docs/Governance.md)
- [Build SDK and run tests](docs/GettingStartedDocs/Contributors/building_oe_sdk.md)

Licensing
=========

This project is released under the
[MIT License](https://github.com/openenclave/openenclave/blob/master/LICENSE).
