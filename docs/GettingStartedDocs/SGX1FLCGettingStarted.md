Getting Started with Open Enclave in SGX1-FLC mode 
=====================================================

### Platform requirements

- Ubuntu 16.04-LTS 64-bits
- SGX1 capable system with Flexible Launch Control support

      Mostly likely, it's a Coffeelake system.

### Obtain Open Enclave source code and install package dependencies

   - Clone Open Enclave SDK repo from GitHub

       Use the following command to download the source distribution.

         $ git clone https://github.com/Microsoft/openenclave

        This creates a source tree under the directory called openenclave.

   - [Install Clang-7](prerequisites.md#install-clang-7)

   - Install all the other prerequisites

      The  [scripts/install-prereqs script](/scripts/install-prereqs) script was created to make installing the prerequisites less tedious. Execute the following commands from the root of the source tree to install above prerequisites.

            $ cd openenclave
            $ sudo ./scripts/install-prereqs

### Install Intel SGX FLC support software packages

 There are two packages needed here:
 
- Intel(R) SGX driver with FLC support
- Intel(R) NGSA SDK

To install these prerequisites type the following commands from the root of
the source distribution.

```
$ sudo make -C prereqs USE_LIBSGX=1
$ sudo make -C prereqs install USE_LIBSGX=1
```

### Build

To build, pick a directory to build under ("build/" below). Then use cmake to configure
the build and generate the make files and build.

```
$ mkdir build/
$ cd build/
build$ cmake .. -DUSE_LIBSGX=1
build$ make
```

Note: Optional detailed build information could be found [here](advancedBuildInfo.md)

### Run unittests

  After building, run all unit test cases via the following ctest command to confirm 
  SDK is built and working as expected.

```
build$ ctest
```
 
        You should see test log like the following:

        youradminusername@yourVMname:~/openenclave/build$  ctest

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
      youradminusername@yourVMname:~/openenclave/build$

A clean pass of above unitests run is an indication that your Open Enclave setup was successful. You can start playing with those Open Enclave samples after following the instructions in the "Install" section below to configure samples for building,

Note: Optional test detailed information could be found [here](AdvancedTestInfo.md)

### Install

 Follow the instructions [here](InstallInfo.md) to install the Open Enclave SDK built above.
 
