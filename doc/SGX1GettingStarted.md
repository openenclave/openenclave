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

**SGX mode** requires SGX-1 hardware support and additional package dependencies
depending on your level of SGX hardware:

_For Skylake and Kabylake systems (SGX-1):_

- Intel(R) SGX driver
- Intel(R) AESM service

To install these prerequisites type the following commands from the root of
the source distribution.

```
$ sudo ./scripts/install-prereqs
$ sudo make -C prereqs
$ sudo make -C prereqs install
```

_For Coffeelake systems (SGX-1 with Flexible Launch Control):_

- Intel(R) SGX driver with FLC support
- Intel(R) NGSA SDK

To install these prerequisites type the following commands from the root of
the source distribution.

```
$ sudo ./scripts/install-prereqs
$ sudo make -C prereqs USE_LIBSGX=1
$ sudo make -C prereqs install USE_LIBSGX=1
```

### Building

Build is generally out-of-tree (in-tree is possible, though not recommended).
To build, pick a directory to build under ("build/" below). Then use cmake to configure
the build and generate the out-of-tree make files and build.

_For Skylake and Kabylake systems (SGX-1):_
```
$ mkdir build/
$ cd build/
build$ cmake ..
build$ make
```

_For Coffeelake systems (SGX-1 with Flexible Launch Control):_
```
$ mkdir build/
$ cd build/
build$ cmake .. -DUSE_LIBSGX=1
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
build$ cmake -DCMAKE_INSTALL_PREFIX:PATH=~/openenclave ..
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

