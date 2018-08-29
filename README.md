Open Enclave SDK
================

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

Design Overview
-------------

The [Design Overview](docs/DesignOverview.pdf) document provides a brief design overview of the Open Enclave SDK. It describes the parts of the SDK and how they work together to create, invoke, and terminate enclaves. 

Getting Started
---------------

For Open Enclave application developers, start [here](docs/GettingStartedDocs/GettingStarted_User.md)

For advanced developers, who not only want to experience Open Enclave applications but also want to dig into how Open Enclave was implemented, and potentially contribute to this open source effort, start [here](docs/GettingStartedDocs/GettingStarted.md)

Contributing
------------

This project welcomes contributions and suggestions. Most contributions require you to agree to a Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us the rights to use your contribution. For details, see [Contributing to Open Enclave](docs/Contributing.md).

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

See the [Development Guide](docs/DevelopmentGuide.md) for details about developing code in this repo, such as coding style and development processes.


Licensing
=========

Microsoft plans to release the [Open Enclave SDK under the MIT license](https://github.com/Microsoft/openenclave/blob/master/LICENSE)
