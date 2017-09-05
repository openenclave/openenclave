Microsoft(R) OpenEnclave SDK
============================

# OpenEnclave

Introduction
------------

OpenEnclave is an SDK for builiding enclave applications in C and C++. An
enclave application partitions itself into a trusted component (called the
host) and an untrusted compoment (called the enclave). An enclave is a secure
container whose memory is protected from entities outside the enclave. These 
protections allow enclaves to perform secure computations with assurances that 
secrets will not be compromised.

The current implementation of OpenEnclave is built on the Intel Software Guard 
Extensions (SGX), although OpenEnclave may support other memory protection
architectures in the future, such as Microsoft Virtual Secure Mode.

The OpenEnclave project provides the following documents.

- [OpenEnclave Design Overview](doc/DesignOverview.pdf)

- [Getting Started with OpenEnclave](doc/GettingStarted.pdf)

- [OpenEnclave Reference Manual](doc/ReferenceManual.txt)

Contributing
------------

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
