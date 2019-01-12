Windows Development for SGX
=============

This document provides steps for developing a Windows host app running on SGX hardware,
or running on simulated SGX or OP-TEE.

For details on Linux Host development see the [Linux ARM documentation.](linux_arm_dev.md).

# Prerequisites

You need to set up a development environment to build the Windows binaries:

- [Microsoft Visual Studio 2017](https://www.visualstudio.com/downloads/)  
  In the Visual Studio Installer, the following is required:
  - Workloads:
    - Desktop development with C++
  - Individual components:
    - VC++ 2017 version 15.9 v14.19 Libs for Spectre (ARM)
    - VC++ 2017 version 15.9 v14.19 Libs for Spectre (x86 and x64)
    - Visual C++ tools for CMake
    - Windows 10 SDK (10.0.16299 or later)
  - The installer may automatically select dependent items.

To support Intel SGX on Windows, the Open Enclave SDK currently relies on having the 
[Intel® Software Guard Extensions (SGX) SDK](https://software.intel.com/sites/default/files/managed/d1/0a/Intel-SGX-SDK-Release-Notes-for-Windows-OS.pdf)
installed. This is because it requires using the `sgx_edger8r.exe` utility that comes
with that SDK as well as various header files. The Intel SGX SDK also provides Visual Studio integration.

You also need the 
[Intel® SGX Platform Software for Windows (PSW)](https://software.intel.com/sites/default/files/managed/0f/c8/Intel-SGX-PSW-Release-Notes-for-Windows-OS.pdf).

Both the SDK and PSW are available for free from Intel:

* [Intel® Software Guard Extensions (SGX) Downloads](https://software.intel.com/en-us/sgx-sdk/download)

**Note:** The dependency on Intel's SGX SDK is temporary.

You may need to restart your environment after installing the Intel SGX SDK.
The PSW should be installed automatically on Windows 10 with the Fall Creators Update installed.
See [troubleshooting](../../docs/GettingStartedDocs/GettingStarted.Windows.md#troubleshooting).

Building applications using the Open Enclave SDK also requires `oeedger8r`, 
the source for which is part of this SDK.
However, a pre-built binary can also be downloaded directly from [here](https://oedownload.blob.core.windows.net/binaries/oeedger8r.exe).
Scripts in the build process download this for you.

# Working with the SDK

## Cloning the SDK

This project uses submodules to pull and keep track of external dependencies. 
Some of these recursively have submodules themselves. 
When cloning, be sure to fetch all submodules recursively, and to update submodules
recursively when you pull, too:

```
git clone https://github.com/Microsoft/openenclave --recurse-submodules -b feature.new_platforms
```

## Building

To build for Windows open the following CMakeLists.txt file with Visual Studio 2017 via File -> Open -> CMake...:

```
 openenclave\new_platforms\CMakeLists.txt
 ```

The solution contains all libraries and samples needed to build the SDK. 
From the configuration drop-down in the top toolbar in Visual Studio, select the platform, TEE and configuration combination to build. The first time, this kicks off CMake in the background to configure the project. When done, select CMake -> Build All.

### Note on configuration support

For this preview, the SDK does not fully support building SGX enclaves targeted for release.
The configuration options supported allow for debug builds that can run on real hardware and
debug simulated builds that can be used as part of your development cycle.

**Note:** The solution can build ARM Hosts for Windows running in the REE. This preview does not have complete support for this yet, but it is coming soon. Building for ARM requires the [Windows Driver Kit for ARM](https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk) (note that the version of the WDK must be equal to the latest version of the Windows 10 SDK installed on the build system).

| Configuration              | Platform  | Usage                                                  |
| -------------------------- | --------- | ------------------------------------------------------ |
| x86-SGX-Debug              | x86       | Builds an x86 SGX enclave and an x86 host app          |
| x86-SGX-Simulation-Debug   | x86       | Builds an x86 SGX simulated enclave and x86 host app   |
| x64-SGX-Debug              | x64       | Builds an x64 SGX enclave and an x64 host app          |
| x64-SGX-Simulation-Debug   | x64       | Builds an x64 SGX simulated enclave and x64 host app   |
| arm-ARMTZ-Debug            | ARM       | An ARM Windows host app *                              |
| arm-ARMTZ-Release          | ARM       | An ARM Windows host app (optimizations & no symbols) * |
| x86-ARMTZ-Simulation-Debug | x86       | Builds an OP-TEE simulated enclave and an x86 host app |

* A non-simulated OP-TEE enclave must be built on Linux or using Bash on Ubuntu on Windows via the Windows Subsystem for Linux (WSL).

### Build Artifacts

All built binaries can be found under:

```
%USERPROFILE%\<workspace hash>\<configuration>
```

# Simulation
The Open Enclave SDK adds two additional methods of simulated debugging with Windows as a Host.

## SGX Simulation

This method uses the Intel SGX SDK for emulation support. Simulation mode does not exercise the hardware, but works similarly to a debug build. For more details, see [Intel SGX Simulation Mode](https://software.intel.com/en-us/blogs/2016/05/30/usage-of-simulation-mode-in-sgx-enhanced-application).

The simulator implements a Visual Studio extension that allows you to debug your enclave using the Intel SGX Debugger. Both x86 and x64 platforms are supported.

To build using SGX Simulation, build using one of the following configurations: `x86-SGX-Simulation-Debug` or `x64-SGX-Simulation-Debug`.

## OP-TEE Simulation

OP-TEE Simulation mode compiles your enclave against a set of in-process libraries that simulate the subset of the functionality that is required from OP-TEE, including ECALL and OCALL support.
This is intended to serve as a quick verification of your code to decrease turn-around time. No hardware environment is emulated.

To build using OP-TEE Simulation, build using the `x86-ARMTZ-Simulation-Debug` configuration.

# Next Steps

Now that you have built the SDK and sample, you can either run the sample, try out simulation, or jump into creating your own enclave:

* [Running the Sample EchoSockets](sample_sockets.md#sgx)
* [Developing your own enclave](new_platform_dev.md)
