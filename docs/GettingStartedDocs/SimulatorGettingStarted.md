# Getting Started with Open Enclave in Simulator mode

## Platform requirement

- Ubuntu 16.04-LTS 64-bits

## Clone Open Enclave SDK repo from GitHub

Use the following command to download the source code.

```bash
git clone https://github.com/Microsoft/openenclave.git
```

This creates a source tree under the directory called openenclave.

## Install project prerequisites

Ansible is required to install the project prerequisites. If not already installed, you can install it by running: `scripts/ansible/install-ansible.sh`
The ansible-playbook [scripts/ansible/ansible-include_task.yml](/scripts/ansible/ansible-include_task.yml) was created to be able to run pre-defined ansible tasks on a target host. All the tasks required to install the prerequisites can be found in the following ansible task list : [scripts/ansible/tasks/ansible-install-prereqs.yml](/scripts/ansible/tasks/ansible-install-prereqs.yml) To make installing the prerequisites less tedious execute the following commands from the root of the source tree:

```bash
cd openenclave
ansible-playbook scripts/ansible/ansible-include_task.yml --extra-vars "target=localhost included_task=tasks/ansible-install-prereqs.yml"
```

## Build

To build first create a build directory ("build/" in the example below) and change into it.

```bash
mkdir build/
cd build/
```

Then run `cmake` to configure the build and generate the make files and build:

```bash
cmake -DUSE_LIBSGX=OFF ..
make
```

Refer to the [Advanced Build Information](AdvancedBuildInfo.md) documentation for further information.

## Run unittests

After building, run all unit test cases using `ctest` to confirm the SDK is built and working as expected. Note that in simulator mode the `OE_SIMULATION` environment must be set.

Run the following command from the build directory:

```bash
OE_SIMULATION=1 ctest
```

You will see test logs similar to the following:

```bash
~/openenclave/build$ OE_SIMULATION=1 ctest
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
```

Some of the tests are skipped (Not Run) by design because the current simulator is not fully featured yet.

A clean pass of the above unitests run is an indication that your Open Enclave setup was successful. You can start playing with those Open Enclave samples after following the instructions in the "Install" section below to configure samples for building,

For more information refer to the [Advanced Test Info](AdvancedTestInfo.md) document.

## Install

 Follow the instructions in the [Install Info](InstallInfo.md) document to install the Open Enclave SDK built above.
