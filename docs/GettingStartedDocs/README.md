Getting Started With Open Enclave
=================================

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

Hardware Drivers
---------------

Open Enclave provides a consistent abstraction across different hardware Enclave
platforms. If you're just getting started, you can compile and test your apps
without an enclave, or you can use one of
the hardware types below.


### Intel SGX

If you would like to start developing apps with the preview Open Enclave SDK
release, start here for instructions to install and use the SDK package:

- [Ubuntu 18.04 with SGX hardware](install_oe_sdk-Ubuntu_18.04.md)
- [Ubuntu 16.04 with SGX hardware](install_oe_sdk-Ubuntu_16.04.md)
- [Ubuntu 18.04 or 16.04 in simulation mode](install_oe_sdk-Simulation.md)
- [Windows Server 2016 with SGX hardware](install_oe_sdk-Windows.md)

If you would like to run Ubuntu 16.04 or Ubuntu 18.04 in a Hyper-V VM on SGX
capable hardware, see
[Setting up a Linux Hyper-V VM on Windows with SGX Support](HyperVLinuxVMSetup.md).

### OP-TEE OS (ARM TrustZone)

The Open Enclave SDK provides preview support for the Open Portable TEE OS
(OP-TEE OS). OP-TEE is an operating system for TEE's that implement a
traditional kernel-mode and user-mode execution environment. It runs on
A-profile ARM systems that support ARM TrustZone. As a result, the Open Enclave
SDK can be leveraged to target these systems as well.

For an overview of the SDK's support for OP-TEE OS as well as links to getting
started guides, see
[Open Enclave SDK for OP-TEE OS](OP-TEE/Introduction.md).

API Documentation
-----------------

The Doxygen-generated documentation corresponding to the APIs currently
supported by the master branch is
[here](https://openenclave.github.io/openenclave/api/index.html). API
Documentation for previous releases of the SDK can be found on the
[Open Enclave SDK website](https://openenclave.io/sdk).

Community
---------

The Open Enclave community is a safe and welcoming environment. We follow a
[Code of Conduct](../CODE_OF_CONDUCT.md) adapted from the
[Contributor Covenant v1.4](https://www.contributor-covenant.org).

Want to get involved? Head on over to the [Community](../Community/README) pages!

If you're interested in how this project is run, head on over to the
[Overview of the Project Governance Model](../Community/Governance.md).

Contributing
------------

If you are interested in contributing changes to Open Enclave, here are some
good places to start:

- [General Development Guide](../Community/DevelopmentGuide.md)
- [How To Build OE SDK and run tests](Contributors/building_oe_sdk.md)

Contributors must sign a
[Developer Certificate of Origin (DCO)](https://developercertificate.org/). For
details, see [Contributing to Open Enclave](../Community/Contributing.md).
