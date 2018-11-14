# Getting Started with Open Enclave in SGX1-FLC mode

## Platform requirements

- Ubuntu 16.04-LTS 64-bits
- SGX1 capable system with Flexible Launch Control support. Most likely this will be an Intel Coffeelake system.

## Clone Open Enclave SDK repo from GitHub

Use the following command to download the source code.

```bash
git clone https://github.com/Microsoft/openenclave.git
```

This creates a source tree under the directory called openenclave.

## Install project prerequisites

The script [scripts/install-prereqs](/scripts/install-prereqs) was created to make installing the prerequisites less tedious. Execute the following commands from the root of the source tree:

```bash
cd openenclave
sudo ./scripts/install-prereqs
```

If you are running in an Azure Confidential Compute VM and would like to use the attestation features, you should also run the following command from the root of the source tree:

```bash
sudo make -C prereqs/az-dcap-client install
```

## Install Intel SGX FLC support software packages

There are two Intel packages needed for SGX1-FLC:

- Intel(R) SGX driver with FLC support
- Intel(R) SGX DCAP SDK

To install these prerequisites type the following commands from the root of
the source distribution.

```bash
sudo make -C prereqs USE_LIBSGX=1
sudo make -C prereqs install USE_LIBSGX=1
```

## Build

To build first create a build directory ("build/" in the example below) and change into it.

```bash
mkdir build/
cd build/
```

Then run `cmake` to configure the build and generate the make files and build:

```bash
cmake .. -DUSE_LIBSGX=1
make
```

Open Enclave will support attestation workflows outside of Azure using DCAP in an upcoming release.

Refer to the [Advanced Build Information](AdvancedBuildInfo.md) documentation for further information.

## Run unittests

After building, run all unit test cases using `ctest` to confirm the SDK is built and working as expected.

Run the following command from the build directory:

```bash
ctest
```

You will see test logs similar to the following:

```bash
~/openenclave/build$  ctest

Test project /home/youradminusername/openenclave/build
      Start   1: tests/aesm
1/123 Test   #1: tests/aesm ...............................................................................................................   Passed    0.98 sec
      Start   2: tests/mem
2/123 Test   #2: tests/mem ................................................................................................................   Passed    0.00 sec
      Start   3: tests/str
3/123 Test   #3: tests/str ................................................................................................................   Passed    0.00 sec
....
....
....
122/123 Test #122: tools/oedump .............................................................................................................   Passed    0.00 sec
            Start 123: oeelf
123/123 Test #123: oeelf ....................................................................................................................   Passed    0.00 sec

100% tests passed, 0 tests failed out of 123

Total Test time (real) =  83.61 sec
```

A clean pass of the above unitests run is an indication that your Open Enclave setup was successful. You can start playing with the Open Enclave samples after following the instructions in the "Install" section below to configure samples for building,

For more information refer to the [Advanced Test Info](AdvancedTestInfo.md) document.

## Install

Follow the instructions in the [Install Info](InstallInfo.md) document to install the Open Enclave SDK built above.
