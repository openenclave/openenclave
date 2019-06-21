Open Enclave SDK
================

[![Join the chat at https://gitter.im/openenclave/community](https://badges.gitter.im/openenclave/community.svg)](https://gitter.im/openenclave/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

Introduction
------------

Open Enclave (OE) is an SDK for building enclave applications in C and C++. An
enclave application partitions itself into two components (1) An untrusted component (called the
host) and (2) A trusted component (called the enclave). An enclave is a secure
container whose memory is protected from entities outside the enclave. These
protections allow enclaves to perform secure computations with assurances that
secrets will not be compromised.

This SDK is a fully open-source and transparent project, which plans to generalize enclave application models across
enclave implementations from different hardware vendors. It's a non-vendor specific solution that supports enclave applications both on
Linux and Windows platforms.

The current implementation of Open Enclave is built on [Intel Software Guard Extensions (SGX)](https://software.intel.com/en-us/sgx), other enclave architectures (such as solutions from AMD or ARM) will be added in the future. This public preview focuses on the Linux platform.


Getting Started
---------------

If you would like to start developing apps with the preview Open Enclave SDK release,
start here for instructions to install and use the SDK package:
- [Ubuntu 16.04](docs/GettingStartedDocs/install_oe_sdk-Ubuntu_16.04.md)
- [Ubuntu 18.04](docs/GettingStartedDocs/install_oe_sdk-Ubuntu_18.04.md)

If you would like to modify and build the Open Enclave SDK from sources, refer to
the documents for [getting started](docs/GettingStartedDocs/Contributors/building_oe_sdk.md).

Contributing
------------

This project welcomes contributions and suggestions. Most contributions require you to agree to a Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us the rights to use your contribution. For details, see [Contributing to Open Enclave](docs/Contributing.md).

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

See the [Development Guide](docs/DevelopmentGuide.md) for details about contributing code to this project, such as coding style and development processes.


Licensing
=========

This project is released under the [MIT License](https://github.com/openenclave/openenclave/blob/master/LICENSE).
