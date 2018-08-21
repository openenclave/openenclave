Obtain the source distribution
=================================
Open Enclave is available from GitHub. Use the following command to download the source distribution.

    # git clone https://github.com/Microsoft/openenclave
This creates a source tree under the directory called openenclave.

Source tree layout
------------------
The files and directories in the top-level directory are described as follows.

- [LICENSE](LICENSE) - The Open Enclave license
- [README.md](README.md) - This README file
- [3rdparty](3rdparty) - Contains third-party software packages
- [cmake](cmake) - Contains CMake scripts for building Open Enclave.
- [common](common) - Contains sources that work in the enclave and the host
- [docs](docs) - Contains documentation
- [core](core) - Contains the source for the oecore library
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

Install Prerequisites
======================
The following are prerequisites for building and running Open Enclave.

- Ubuntu Desktop-16.04-LTS 64bits
- Various packages: build-essential, ocaml, automake, autoconf, libtool, wget, python, 
                    libssl-dev, libcurl4-openssl-dev, protobuf-compiler, libprotobuf-dev, 
                    build-essential, python, libssl-dev, libcurl4-openssl-dev, libprotobuf-dev, 
                    uuid-dev, libxml2-dev, cmake, pkg-config

Execute the following commands from the root of the source tree to install above prerequisites for you

```
$ cd openenclave
$ sudo ./scripts/install-prereqs
```
