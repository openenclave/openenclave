Open Enclave SDK
================

[![Build Status](https://oe-jenkins.eastus.cloudapp.azure.com/buildStatus/icon?job=OpenEnclave-nightly_packages)](https://oe-jenkins.eastus.cloudapp.azure.com/job/OpenEnclave-nightly_packages/) [![Join the chat at https://gitter.im/openenclave/community](https://badges.gitter.im/openenclave/community.svg)](https://gitter.im/openenclave/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

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
from different hardware vendors. While the current implementation is focused on
Intel SGX, support for ARM TrustZone is already under development. As an open
source project, this SDK also strives to provide a transparent solution that is
agnostic to specific vendors, service providers and choice of operating systems.

Getting Started
---------------

If you would like to start developing apps with the preview Open Enclave SDK
release, start here for instructions to install and use the SDK package:

- [Ubuntu 18.04 with SGX hardware](docs/GettingStartedDocs/install_oe_sdk-Ubuntu_18.04.md)
- [Ubuntu 16.04 with SGX hardware](docs/GettingStartedDocs/install_oe_sdk-Ubuntu_16.04.md)
- [Ubuntu 18.04 or 16.04 in simulation mode](docs/GettingStartedDocs/install_oe_sdk-Simulation.md)
- Windows Release Package coming soon

If you would like to modify and build the Open Enclave SDK from sources, refer
to the documents for [getting started](docs/GettingStartedDocs/Contributors/building_oe_sdk.md).

Contributing
------------

This project welcomes contributions and suggestions. Most contributions require
you to agree to a Contributor License Agreement (CLA) declaring that you have
the right to, and actually do, grant us the rights to use your contribution. For
details, see [Contributing to Open Enclave](docs/Contributing.md).

This project has adopted the
[Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the
[Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/)
or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any
additional questions or comments.

See the [Development Guide](docs/DevelopmentGuide.md) for details about
contributing code to this project, such as coding style and development
processes. Also see our [Governance Model](docs/GovernanceModel.md) for how we
maintain the project.

Licensing
=========

This project is released under the
[MIT License](https://github.com/openenclave/openenclave/blob/master/LICENSE).
