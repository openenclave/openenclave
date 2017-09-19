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

Documentation
-------------

The OpenEnclave project provides the following documents.

- [OpenEnclave Design Overview](doc/DesignOverview.pdf)

- [Getting Started with OpenEnclave](doc/GettingStarted.md)

- [Open Enclave Function Reference](doc/refman/md/index.md)

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

License
-------

```
MIT License

Copyright (c) Microsoft Corporation. All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE
```

Code of Conduct
---------------

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
