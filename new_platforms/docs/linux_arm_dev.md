Linux Development
=============

This guide shows you how to obtain and build the SDK as well as the samples and
test code that it includes with host apps on Linux and enclaves on ARM
TrustZone. For an architectural overview see [ARM TrustZone and SGX deep
dive](sgx_trustzone_arch.md). You can also use the [Open Enclave extension for
Visual Studio Code](../vscode-extension/README.md) that automates the steps
presented in this document.

For details on Windows development, see [Windows Development](win_sgx_dev.md).

To work in a simulated ARM TrustZone environment, see [Debugging OP-TEE TAs with
QEMU](ta_debugging_qemu.md).

**Note**: The only currently supported build environment is Ubuntu 18.04.1.

# Prerequisites

Building applications using this SDK requires
[oeedger8r](https://github.com/Microsoft/openenclave/tree/master/docs/GettingStartedDocs/Edger8rGettingStarted.md),
the source for which is part of this SDK. The build script downloads a pre-built
binary for you from [this
location](https://oedownload.blob.core.windows.net/binaries/oeedger8r).

# Getting the SDK

This project uses submodules to pull and keep track of external dependencies.
Some of these recursively have submodules themselves. When cloning, be sure to
fetch all submodules recursively, and to update submodules recursively when you
pull, too:

```
git clone https://github.com/Microsoft/openenclave --recurse-submodules -b feature.new_platforms
```

# Building the SDK

The Open Enclave SDK has a top-level CMake-based build system. Currently, the
top-level `CMakeLists.txt` is disconnected from the one under `new_platforms`.
Hence, to use the support for new platforms in this preview, use the
`CMakeLists.txt` file under `new_platforms`.

A Bash script is provided that automates the process of installing all
prerequisites and invoking the relevant CMake commands.

## Building for Scalys LS1012 Grapeboard

The steps below assume that you are targetting a [Scalys LS1012
Grapeboard](grapeboard.mc). For details on the build process, and how to build
other architectures, see [Build Process
Details](linux_arm_dev.md#build-process-details).

1) Start by setting the following exports:
   * `ARCH` specifies the target architecture. The Grapeboard is ARMv8, so set
     this to `aarch64`.
   *  `MACHINE` specifies the target board. For the Grapeboard, use
      `ls1012grapeboard`.
    ```
    export ARCH=aarch64
    export MACHINE=ls1012grapeboard
    ```
2) Next, we can run a batch script that installs all dependencies and builds the
   Open Enclave SDK and samples. This builds REE and TEE components:
    ```
    ./new_platforms/scripts/build_optee.sh
    ```

## Build Artifacts

The `sockets` sample generates three binaries:

* `scripts/build/<arch>/out/bin/socketclient_host`
* `scripts/build/<arch>/out/bin/socketserver_host`
* `scripts/build/<arch>/out/bin/aac3129e-c244-4e09-9e61-d4efcf31bca3.ta`

In order to run the sample, you must copy these files to the target. The host
apps may reside anywhere on the target's filesystem. However, the TA file must
be placed in a specific folder where all the TA's are placed. For all
architectures and machines currently supported, this location is:

```
/lib/optee_armtz
```

## Running the Samples

To run the `SampleClient` and `SampleServer` samples, see the [echo socket
sample](sample_sockets.md#grapeboard).

# Build Process Details

Due to the design of ARM TrustZone, trusted applications must be compiled once
for each specific board you want to run them on. OP-TEE OS provides a layer of
abstraction atop raw hardware and may either be readily built by your hardware
provider or you may build it yourself. OP-TEE OS has support for a variety of
ARM boards and, when it is built, it produces a TA Development Kit not
dissimilar to an SDK. This kit includes header files with definitions for
standard functions as well as GNU Make rules that specify how TA code is to be
built and packaged. As a result, to build a TrustZone TA, you either must have
access to the TA Dev Kit that corresponds to the version of OP-TEE on your board
or you must build it yourself.

For convenience, the Bash script included with the Open Enclave SDK can build
OP-TEE OS for the purposes of obtaining a TA Dev Kit for certain specific
configurations. The configurations are specified using two variables:

* `ARCH` specifies the target architecture:
    * `aarch32` for ARMv7 targets;
    * `aarch64` for ARMv8 targets.
* `MACHINE` specifies the target board.
    * For ARMv7 targets:
        * `virt` builds OP-TEE OS and creates a TA Dev Kit for running emulated
          in QEMU (`qemu-system-arm`).
    * For ARMv8 targets:
        * `ls1012grapeboard` builds OP-TEE OS and a TA Dev Kit for a Scalys
          LS1012 (Grapeboard) board;
        * `virt` builds OP-TEE OS and a TA Dev Kit for running emulated in QEMU
          (`qemu-system-aarch64`).

## Build Script

`build_optee.sh` performs the following steps:

* Installs all build prerequisites;
* Downloads and extracts the Linaro cross-compilers:
    * For `aarch32`, only the arm-on-x86/64 cross-compiler is necessary;
    * For `aarch64`, the aarch64-onx86/64 is necessary in addition to the
      arm-on-x86/64 cross-compiler.
* Downloads the `oeedger8r` tool;
* Builds OP-TEE OS and the associated TA Dev Kit;
* Builds the Open Enclave SDK with samples and test code;
* Executes Doxygen on the SDK.

## Bring Your Own OP-TEE

If you already have a TA Dev Kit, you may specify it as follows just prior to
invoking the script:

```
export TA_DEV_KIT_DIR=<absolute path to the kit>
```

This precludes the script from building OP-TEE and it instead references your TA
Dev Kit.

## Cleaning the SDK

To remove all output generated by the script, simply delete the
architecture-specific directories under under `new_platforms/scripts/build`.

# Next Steps

The easiest way to get started with creating a new host and TA pair is by taking
the existing samples and modifying them to suit your needs. The `sockets` sample
is simple in nature but provides all the structure you need to be well on your
way to creating your own TEE-enabled applications.

* [Building the Sample EchoSockets](sample_sockets.md#grapeboard)
* [Developing your own enclave](new_platform_dev.md)
