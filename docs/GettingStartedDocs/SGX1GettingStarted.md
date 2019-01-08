# Getting Started with Open Enclave in SGX1 mode

## Platform requirements

- Ubuntu 16.04-LTS 64-bits
- SGX1 capable system. Most likely this will be an Intel SkyLake or Intel KabyLake system

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

## Install Intel SGX1 support software packages

There are two Intel packages needed for SGX1:

- Intel® SGX Driver (/dev/isgx)
- Intel® SGX AESM Service (from the Intel® SGX SDK)

Refer to the [Intel® SGX Driver](https://github.com/01org/linux-sgx-driver) and [Intel® SGX AESM Service](https://github.com/01org/linux-sgx) github repositories for detailed instructions on how to build and install these packages.

As a convenience, Open Enclave provides a script for downloading, building and
installing both the driver and the AESM service. To install these dependencies
type the following commands from the root of the source distribution:

```bash
sudo make -C prereqs
sudo make -C prereqs install
```

After this completes verify that the AESM service is running as follows:

```bash
service aesmd status
```

Look for the string “active (running)”, usually highlighted in green.

## Build

To build first create a build directory ("build/" in the example below) and change into it.

```bash
mkdir build/
cd build/
```

Then run `cmake` to configure the build and generate the make files and build:

```bash
cmake ..
make
```

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
