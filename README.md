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

- [API Documentation](doc/refman/md/index.md)

Source tree layout
------------------

The files and directories in the top-level directory are described as follows.

- [README.md](README.md) - This README file
- [LICENSE](LICENSE) - The OpenEnclave license
- [configure](configure) - Script for configuring the build
- [3rdparty](3rdparty) - Contains third-party software packages
- [enclave](enclave) - Contains the source for the oeenclave library
- [libc](libc) - Contains sources for the oelibc enclave library
- [libcxx](libcxx) - Contains makefile for building the oelibcxx library
- [idl](idl) - Contains source for the oeidl library
- [host](host) - Contains source for the oehost library
- [common](common) - Contains sources that work in the enclave and the host
- [tools](tools) - Contains command-line tools (oesgx, oesign, oegen, oeelf)
- [doc](doc) - Contains documentation
- [include](include) - Contains C header files
- [prereqs](prereqs) - Contains scripts for installing prerequisite software
- [mak](mak) - Contains shared make scripts (the build system)
- [tests](tests) - Constains all test programs, which may also serve as samples
- [samples](samples) - Constains enclave-development sample sources
- [scripts](scripts) - Contains Shell scripts

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
