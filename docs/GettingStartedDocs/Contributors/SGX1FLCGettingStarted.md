# Getting Started with Open Enclave in SGX1-FLC mode

## Platform requirements

- Ubuntu 20.04 or 22.04 LTS 64-bit.
- SGX1 capable system with Flexible Launch Control support. Most likely this will be an Intel Coffeelake system.

## Clone Open Enclave SDK repo from GitHub

Use the following command to download the source code.

```bash
git clone --recursive https://github.com/openenclave/openenclave.git
```

This creates a source tree under the directory called openenclave.

## Install project requirements

First, change directory into the openenclave repository:
```bash
cd openenclave
```

Ansible is required to install the project requirements. If not already installed, you can install it by running:
```bash
sudo scripts/ansible/install-ansible.sh
```

If you are running in an Azure Confidential Compute (ACC) VM and would like to use the attestation features, you should also run the following command from the root of the source tree:

```bash
ansible-playbook scripts/ansible/oe-contributors-acc-setup.yml
```

If you are not running in an ACC VM, you should instead run:

```bash
ansible-playbook scripts/ansible/oe-contributors-setup.yml
```

To learn more about setting up Open Enclave SGX on Linux in a Non-Azure Confidential Computing machine, read the document [Configure OE SDK SGX on Linux in non-ACC Machines](/docs/GettingStartedDocs/Contributors//NonAccMachineSGXLinuxGettingStarted.md).

To support LVI mitigation, the command creates
`/usr/local/lvi-mitigation/bin` that includes the dependencies.

NOTE: The Ansible playbook commands from above will try and execute tasks with `sudo` rights. Make sure that the user running the playbooks has `sudo` rights, and if it uses a `sudo` password add the following extra parameter `--ask-become-pass`.

## Build

To build, first create a build directory ("build" in the example below) and change directory into it.

```bash
mkdir build
cd build
```

Then run `cmake` to configure the build and generate the Makefiles, and then build by running `make` or 'ninja' depending:

```bash
cmake -G "Unix Makefiles" ..
make
```
or
```bash
cmake -G "Ninja" ..
ninja
```

To build with LVI mitigation, run

```bash
cmake -G "Ninja" .. \
-DLVI_MITIGATION=ControlFlow \
-DLVI_MITIGATION_BINDIR=/usr/local/lvi-mitigation/bin
ninja
```

Refer to [Advanced Build Information](AdvancedBuildInfo.md) and
[LVI Mitigation](AdvancedBuildInfo.md#lvi-mitigation) documentation for further information.

## Run unit tests

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

A clean pass of the above unit tests is an indication that your Open Enclave setup was successful.

You can start playing with the Open Enclave samples after following the instructions in the "Install" section below to configure samples for building,

For more information refer to the [Advanced Test Info](AdvancedTestInfo.md) document.

## Install

Follow the instructions in the [Install Info](LinuxInstallInfo.md) document to install the Open Enclave SDK built above.

## Build and run samples

To build and run the samples, please look [here](/samples/README.md).

## Determine call path for SGX quote generation in attestation sample

In the attestation sample, you can either take the in-process call path or out-of-process call path to generate evidence of format `OE_FORMAT_UUID_SGX_ECDSA`. If you wish to specify the call path it takes to generate a quote, here is what you can do:
* To perform in-process quote generation, unset the environment variable `SGX_AESM_ADDR` and ensure that the DCAP library is installed.
* To perform out-of-process quote generation, set the environment variable `SGX_AESM_ADDR` to any value and ensure that SGX SDK quote-ex Library is installed.

If `SGX_AESM_ADDR` is not set, one can run an existing OE app with out-of-process attestation, using `$ SGX_AESM_ADDR=1 <app_name>`.
* If `SGX_AESM_ADDR=1` is added to `/etc/environment` instead, then it will set `SGX_AESM_ADDR` for the whole system. To unset it for the whole system, simply remove the line. These actions require elevated privileges.
* If `SGX_AESM_ADDR` is set by default globally, to run an existing OE app with in-process attestation, one can use `$ env -u SGX_AESM_ADDR <app_name>`.

Please refer to the following document for more information:
* [Attestation: OE SDK Integration with Intel® SGX SDK quote-ex Library for Generation of Evidence in New Formats](https://github.com/openenclave/openenclave/blob/master/docs/DesignDocs/SGX_QuoteEx_Integration.md)
