
Getting Started with Open Enclave in Simulator mode 
=====================================================

### Platform requirement

- Ubuntu 16.04-LTS 64-bits

### Obtain Open Enclave source code and install package dependencies

   - Clone Open Enclave SDK repo from GitHub

       Use the following command to download the source distribution.

        $ git clone https://github.com/Microsoft/openenclave

        This creates a source tree under the directory called openenclave.

   - Install Prerequisites

      The  [scripts/install-prereqs script](/scripts/install-prereqs) script was created to make installing the prerequisites less tedious. Execute the following commands from the root of the source tree to install above prerequisites for you

            $ cd openenclave
            $ sudo ./scripts/install-prereqs

### Build

To build, pick a directory to build under ("build/" below). Then use cmake to configure
the build and generate the make files and build.

    $ mkdir build/
    $ cd build/
    build$ cmake ..
    build$ make

Note: Optional detailed build information could be found [here](advancedBuildInfo.md)

### Run unittests

  After building, run all unittest cases using the following ctest command to confirm 
  SDK is built and working as expected

    build$ OE_SIMULATION=1 ctest
    
  You should see test output like the following:
  
    For example:
        youradminusername@yourVMname:~/openenclave/build$ OE_SIMULATION=1 ctest
        Test project /home/youradminusername/openenclave/build
                Start   1: tests/aesm
          1/123 Test   #1: tests/aesm ...............................................................................................................***Skipped   0.00 sec
                Start   2: tests/mem
          2/123 Test   #2: tests/mem ................................................................................................................   Passed    0.00 sec
                Start   3: tests/str
          3/123 Test   #3: tests/str ................................................................................................................   Passed    0.00 sec
        ....
        ....
        ....
        121/123 Test #121: samples ..................................................................................................................   Passed    4.46 sec
                Start 122: tools/oedump
        122/123 Test #122: tools/oedump .............................................................................................................   Passed    0.00 sec
                Start 123: oeelf
        123/123 Test #123: oeelf ....................................................................................................................   Passed    0.00 sec

        93% tests passed, 8 tests failed out of 123

        Total Test time (real) =  38.81 sec

        The following tests FAILED:
                  1 - tests/aesm (Not Run)
                  6 - tests/debug-unsigned (Not Run)
                  7 - tests/debug-signed (Not Run)
                  8 - tests/nodebug-signed (Not Run)
                  9 - tests/nodebug-unsigned (Not Run)
                 33 - tests/report (Not Run)
                 37 - tests/sealKey (Not Run)
                115 - tests/VectorException (Not Run)
        Errors while running CTest
        youradminusername@yourVMname:~/openenclave/build$

Some of the tests are skipped (Not Run), by design, because the current simulator is not fully featured yet.

A clean pass of above unitests run is an indication that your Open Enclave setup was successful. You can start playing with those Open Enclave samples after following the instructions in the "Install" section below to configure samples for building,

Note: Optional test detailed information could be found [here](AdvancedTestInfo.md)
   
### Install

 Follow the instructions [here](InstallInfo.md) to install SDK the compiled Open Enclave
