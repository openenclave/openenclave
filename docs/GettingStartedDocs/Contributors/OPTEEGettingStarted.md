# Getting Started with Open Enclave for OP-TEE OS

The Open Enclave SDK as well as hosts and enclaves build via cross-compilation.
Therefore, an ARM system, physical or emulated, is necessary only for execution,
but not for development and building.

## Platform Requirements

- Ubuntu 16.04 LTS (64-bit) or 18.04 LTS (64-bit)

## Clone the Open Enclave SDK

```bash
git clone --recursive https://github.com/openenclave/openenclave.git
```

## Install Build Requirements

Installing the build-time requirements is done via Ansible. The following
command listing shows how to install Ansible, then how to run the Ansible
Playbook that installs the requirements.

```bash
cd openenclave

sudo scripts/ansible/install-ansible.sh
sudo ansible-playbook scripts/ansible/oe-contributors-setup-cross-arm.yml
```

## Build the Open Enclave SDK

Given that each ARM board is different, OP-TEE OS may be configured and built
accordingly. This means that a build of OP-TEE OS for one board is most likely
not compatible with a build of the exact same code for a different board.

During OP-TEE OS' build process, a so-called "Dev Kit" is generated. This kit
contains a number of headers, libraries and configuration files that describe
the settings that were used to build OP-TEE OS for a given board. The Open
Enclave SDK's build process consumes this Dev Kit to in turn configure and link
the components that it leverages to support OP-TEE OS. As a result, it is highly
recommended that you build the SDK from source for each target board so as to
minimize the chance of a configuration mismatch, which, while minimal at the
level of abstraction that the SDK operates at, may nevertheless occur.

Assuming that you have a Dev Kit from an OP-TEE OS build and its location is
stored in the `DEV_KIT` variable, compiling the SDK is simple:

```bash
mkdir build
cd build

cmake ../sdk \
    -G Ninja \
	-DCMAKE_TOOLCHAIN_FILE=../sdk/cmake/arm-cross.cmake \
	-DOE_TA_DEV_KIT_DIR=$DEV_KIT/export-ta_arm64 \
	-DCMAKE_BUILD_TYPE=Debug
ninja
```

The build results in ARM64 binaries.

Refer to the list of
[supported platforms](../OP-TEE/Introduction.md#supported-platforms)
for details on building the SDK for a specific target.

## Remarks

Automatically running unit tests or installing the SDK's build output is not yet
supported when compiling it for OP-TEE OS.
