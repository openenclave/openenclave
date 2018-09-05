
# Install Prerequisites

## Install Prerequisites
======================

 To build the Open Enclave SDK from its source code successfully, you need to install the following 
 packages

   | Packages                          |  depending component|
   |:----------------------------------|:-----------------------------------:|
   | clang-format cmake gcc g++ make   | Needed for Open Enclave build and scripts|
   | gdb                               | Needed for using oedbg                   |
   | autoconf libtool                  | Needed for 3rdparty/libunwind               |
   | doxygen graphviz                  | Needed to generate documentation during make |
   | gawk                              | Needed for cmake/get_c_compiler_dir.sh |
   | libexpat1-dev                     | Needed for dox2md document generation |
   | openssl                           | Needed for oesign |
   | libssl-dev                        | Needed for oehost |
   | subversion                        | Needed for 3rdparty/libcxx/update.make |
   | dh-exec                           | Debian execution helper|
   | libcurl3                          | client-side URL transfers library|

  See [/scripts/install-prereqs](/scripts/install-prereqs) script for a up-to-date list

For application developers: install the following basic runtime prerequisites

     $sudo apt-get clang-format cmake autoconf libtool doxygen graphviz gawk libexpat1-dev openssl subversion

For advanced developers: other than above basic runtime prerequisites, install the following dev environment prerequisites

    $sudo apt-get install make gcc g++ gdb libmbedtls10 libssl-dev dh-exec libcurl3


The "install-prereqs" script was created to make installing the prerequisites less tedious.
Execute the following commands from the root of the source tree to install above prerequisites for you
```
$ cd openenclave
$ sudo ./scripts/install-prereqs
```

## Obtain the source distribution

Open Enclave is available from GitHub. Use the following command to download the source distribution.

    $ git clone https://github.com/Microsoft/openenclave
This creates a source tree under the directory called openenclave.

### Source tree layout

The files and directories in the top-level directory are described as follows.

- [LICENSE](LICENSE) - The Open Enclave license
- [README.md](README.md) - This README file
- [3rdparty](3rdparty) - Contains third-party software packages
- [cmake](cmake) - Contains CMake scripts for building Open Enclave.
- [common](common) - Contains sources that work in the enclave and the host
- [doc](doc) - Contains documentation
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
- [tools](tools) - Contains command-line tools (oesgx, oesign, oegen)


