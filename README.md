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

Documentation
-------------

The Open Enclave project provides the following documents.

- [Getting Started with Open Enclave](doc/GettingStarted.md)

- [Open Enclave Function Reference](doc/refman/md/index.md)

- [Open Enclave Design Overview](doc/DesignOverview.pdf)

The first document explains how to build and use Open Enclave.

Installing
----------

This section explains briefly how to install the Open Enclave SDK from source.
For a detailed explanation, see [Getting Started with
Open Enclave](doc/GettingStarted.md).

### Prerequisites

Open Enclave runs on the following platforms:

- Ubuntu 16.04-LTS 64-bits

It supports two modes: **SGX mode** and **simulation mode**.

**Simulation mode** has package dependencies that may be installed from
the root of the source distribution as follows.

```
$ sudo ./scripts/install-prereqs
```

**SGX mode** has the following prerequisites.

- SGX-1 hardware support
- Intel(R) SGX driver
- Intel(R) AESM service
- Various package dependencies

To install these prerequisites type the following commands from the root of
the source distribution.

```
$ sudo ./scripts/install-prereqs
$ sudo make -C prereqs
$ sudo make -C prereqs install
```

### Building

Build is generally out-of-tree (in-tree is possible, though not recommended).
To build, pick a directory to build under ("build/" below). Then use cmake to configure
the build and generate the out-of-tree make files and build.

```
$ mkdir build/
$ cd build/
build$ cmake ..
build$ make
```

### Running the tests

After building, tests can be executed via ctest, see "man ctest" for details.

For SGX mode, type:

```
build$ ctest
```

For simulation mode, type:

```
build$ OE_SIMULATION=1 ctest
```

### Installing

Specify the install-prefix to the cmake call. As of now, there is no real need to install the SDK
system-wide, so you might use a tree in your home directory:

```
build$ cmake -DCMAKE_INSTALL_PREFIX:PATH=$~/OpenEnclave ..
build$ make install
```

For more details on installation, such as how to create redistributable packages,
see the [Getting Started with Open Enclave](doc/GettingStarted.md) doc.


Source tree layout
------------------

The files and directories in the top-level directory are described as follows.

- [LICENSE](LICENSE) - The Open Enclave license
- [README.md](README.md) - This README file
- [3rdparty](3rdparty) - Contains third-party software packages
- [cmake](cmake) - Contains CMake scripts for building Open Enclave.
- [common](common) - Contains sources that work in the enclave and the host
- [doc](doc) - Contains documentation
- [enclave](enclave) - Contains the source for the oeenclave library
- [host](host) - Contains source for the oehost library
- [idl](idl) - Contains source for the oeidl library
- [include](include) - Contains C header files
- [libc](libc) - Contains sources for the oelibc enclave library
- [libcxx](libcxx) - Contains logic for building the oelibcxx library
- [prereqs](prereqs) - Contains scripts for installing prerequisite software
- [samples](samples) - Contains enclave-development sample sources
- [scripts](scripts) - Contains Shell scripts
- [tests](tests) - Contains all test programs, which may also serve as samples
- [tools](tools) - Contains command-line tools (oesgx, oesign, oegen, oeelf)

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

Contributing
------------
See [Contributing to Open Enclave](doc/Contributing.md) for information about
contributing to the Open Enclave project.

See the [Development Guide](doc/DevelopmentGuide.md) for details about developing
code in this repo, such as coding style and development processes.

Code of Conduct
---------------

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
