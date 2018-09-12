Getting Started with Open Enclave in SGX1 mode 
=====================================================


### Platform requirements

- Ubuntu 16.04-LTS 64-bits
- SGX1 capable system

  Mostly likely, it's either a SkyLake or a KabyLake system

### Obtain Open Enclave source code and install package dependencies

   - Clone Open Enclave SDK repo from GitHub

       Use the following command to download the source distribution.

         $ git clone https://github.com/Microsoft/openenclave

        This creates a source tree under the directory called openenclave.

   - [Install Clang-7](prerequisites.md#install-clang-7)

   - Install all the other prerequisites

      The  [scripts/install-prereqs script](/scripts/install-prereqs) script was created to make installing the prerequisites less tedious. Execute the following commands from the root of the source tree to install above prerequisites for you

            $ cd openenclave
            $ sudo ./scripts/install-prereqs

### Install SGX Intel SGX package dependencies

 In SGX1 mode, it requires additional Intel SGX packages

- Intel® SGX Driver (/dev/isgx)
- Intel® SGX AESM Service (from the Intel® SGX SDK)

The SGX Driver and the AESM Service could be obtained from the following GitHub repositories. 
Both contain detailed instructions about building and installing these pieces.
     
  - <https://github.com/01org/linux-sgx-driver>
  - <https://github.com/01org/linux-sgx>

As a convenience, Open Enclave provides a script for downloading, building and
installing both the driver and the AESM service. To install these dependencies 
type the following commands from the root of
the source distribution, openenclave.

```
$ sudo make -C prereqs
$ sudo make -C prereqs install
```

After this completes, verify that the AESM service is running as follows.
```
$ service aesmd status
```
Look for the string “active (running)”, usually highlighted in green.

### Build

To build, pick a directory to build under ("build/" below).
Then use cmake to configure the build and generate the make files and build.

```
$ mkdir build/
$ cd build/
build$ cmake ..
build$ make
```
Note: Optional detailed build information could be found [here](advancedBuildInfo.md)

### Run unittests

  After building, run all unittest cases via the following ctest command to confirm 
  SDK is built and working as expected.

```
build$ ctest
```
A clean pass of above unitests run is an indication that your Open Enclave setup was successful. You can start playing with those Open Enclave samples after following the instructions in the "Install" section below to configure samples for building,

Note: Optional test detailed test information could be found [here](AdvancedTestInfo.md)

### Install

 Follow the instructions [here](InstallInfo.md) to install SDK the compiled Open Enclave.





