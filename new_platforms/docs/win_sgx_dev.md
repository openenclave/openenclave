Windows Development
=============

This document provides steps for developing a Windows host app and enclave
running on SGX hardware, simulated SGX or OP-TEE.

For details on Linux development, see the [Linux ARM
documentation](linux_arm_dev.md).

# Prerequisites

The Open Enclave SDK has a CMake-based build system. Visual Studio 2017 has
support for CMake whereas previous versions do not.

- Install [Visual Studio 2017](https://visualstudio.microsoft.com/downloads/)  
  In the Visual Studio Installer, select:
  - Workloads
    - Desktop development with C++
  - Individual components
    - VC++ 2017 version 15.9 v14.19 Libs for Spectre (ARM)
    - VC++ 2017 version 15.9 v14.19 Libs for Spectre (x86 and x64)
    - Visual C++ tools for CMake
    - Windows 10 SDK (10.0.16299 or later)

The Visual Studio Installer installs the latest Windows 10 SDK. If you need a
different version, or additional versions, you can configure this in the
individual components tab.

**Note:** The installer may automatically add dependencies as you add
components.

## Intel SGX Prerequisites

To support Intel SGX on Windows, the Open Enclave SDK currently relies on having
the [Intel® Software Guard Extensions (SGX)
SDK](https://software.intel.com/sites/default/files/managed/d1/0a/Intel-SGX-SDK-Release-Notes-for-Windows-OS.pdf)
installed. The Open Enclave SDK makes use of headers and libraries provided by
the Intel SGX SDK. Additionally, the Intel SGX SDK also provides Visual Studio
integration. To execute Intel SGX enclaves on supported hardware, you also need
the [Intel® SGX Platform Software for Windows
(PSW)](https://software.intel.com/sites/default/files/managed/0f/c8/Intel-SGX-PSW-Release-Notes-for-Windows-OS.pdf).
Both the SDK and PSW are available for free from Intel from the [Intel® Software
Guard Extensions (SGX)
Downloads](https://software.intel.com/en-us/sgx-sdk/download) site.

**Note:** The dependency on Intel's SGX SDK is temporary.

You may need to restart your environment after installing the Intel SGX SDK. The
PSW should be installed automatically on Windows 10 with the Fall Creators
Update installed. See
[troubleshooting](../../docs/GettingStartedDocs/GettingStarted.Windows.md#troubleshooting).

Building applications using the Open Enclave SDK also requires `oeedger8r`, the
source for which is part of this SDK. However, a pre-built binary can also be
downloaded directly from
[here](https://oedownload.blob.core.windows.net/binaries/oeedger8r.exe). The
CMake build system downloads this utility for you.

## ARM TrustZone Prerequisites

To build a host app for Windows on ARM, the Open Enclave SDK requires the
[Windows 10 Driver Kit
(WDK)](https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk).
The CMake build system searches the system for the latest Windows SDK and makes
use of the corresponding WDK. As such, the version of the WDK you install must
match that of the latest Windows SDK you have installed. If you require an older
WDK, these can be found
[here](https://docs.microsoft.com/en-us/windows-hardware/drivers/other-wdk-downloads).

# Working with the SDK

## Cloning the SDK

This project uses submodules to pull and keep track of external dependencies.
Some of these recursively have submodules themselves. When cloning, be sure to
fetch all submodules recursively, and to update submodules recursively when you
pull, too:

```
git clone https://github.com/Microsoft/openenclave --recurse-submodules -b feature.new_platforms
```

## Building

To build for Windows, open the following file with Visual Studio 2017 via File
-> Open -> CMake...:

```
openenclave\new_platforms\CMakeLists.txt
```

The solution contains all libraries and samples needed to build the SDK. From
the configurations drop-down in the top toolbar in Visual Studio, select the one
you want to build. The first time a given configuration is selected, Visual
Studio starts CMake in the background to set up the project for that
configuration. When that process is complete, select CMake -> Build All. Visual
Studio's CMake integration pulls IntelliSense configuration information from
CMake. As such, switching between configurations sets up IntelliSense
accordingly, too.

### Build Configurations

For this preview, the SDK does not fully support building SGX enclaves targeted
for release. The configuration options supported allow for debug builds that can
run on real hardware and debug simulated builds that can be used as part of your
development cycle.

**Note:** The solution can build ARM hosts apps for Windows running in the REE.
This preview does not have complete support for this yet, but it is coming soon.

| Configuration              | Platform  | Usage                                                  |
| -------------------------- | --------- | ------------------------------------------------------ |
| x86-SGX-Debug              | x86       | Builds an x86 SGX enclave and an x86 host app          |
| x86-SGX-Simulation-Debug   | x86       | Builds an x86 SGX simulated enclave and x86 host app   |
| x64-SGX-Debug              | x64       | Builds an x64 SGX enclave and an x64 host app          |
| x64-SGX-Simulation-Debug   | x64       | Builds an x64 SGX simulated enclave and x64 host app   |
| arm-ARMTZ-Debug            | ARM       | An ARM Windows host app *                              |
| arm-ARMTZ-Release          | ARM       | An ARM Windows host app (optimizations & no symbols) * |
| x86-ARMTZ-Simulation-Debug | x86       | Builds an OP-TEE simulated enclave and an x86 host app |

* A non-simulated OP-TEE enclave must be built on Linux or using Bash on Ubuntu
  on Windows via the Windows Subsystem for Linux (WSL).

### Build Artifacts

All built binaries can be found under:

```
new_platforms\build\<configuration>\out\bin
```

## Debugging

There are three overarching methods to debugging enclaves. The first allows for
debugging SGX enclaves running in hardware. The second allows for debugging SGX
enclaves in simulation mode. The third allows for debugging ARM TrustZone
enclaves in simulation mode. Debugging ARM TrustZone enclaves running in
hardware is not supported.

### SGX in Hardware

To build and debug SGX enclaves running in hardware, build the Open Enclave SDK
using one of following configurations:

- `x86-SGX-Debug`
- `x64-SGX-Debug`

When done, open a new instance of Visual Studio 2017 and select File -> Open ->
Project/Solution. Then, navigate to where the build artifacts are located for
the configuration you previously built and open the Visual Studio solution
autogenerated by CMake. In the Solution Explorer, find the project that
corresponds to the host app whose enclave you wish to debug, right-click on it
and select Properties. In the properties dialog, select Debugging on the tree on
the left and set the debugger to "Intel(R) SGX Debugger". Then, set the working
directory to the location where the binary artifacts are located. This is
necessary so the host app finds the enclave file.

**Note:** The solution file and its associated projects are automatically
generated by CMake. As such, if any of the `CMakeLists.txt` files change, the
solution and projects may be overwritten.

### SGX in Simulation

This method uses the Intel SGX SDK for emulation support. Simulation mode does
not exercise hardware, but works similarly to a debug build. For more details,
see [Intel SGX Simulation
Mode](https://software.intel.com/en-us/blogs/2016/05/30/usage-of-simulation-mode-in-sgx-enhanced-application).

To build and debugin SGX enclaves running in simulation mode, build the Open
Enclave SDK using one of the following configurations:

- `x86-SGX-Simulation-Debug`
- `x64-SGX-Simulation-Debug`

Follow the same instructions as for SGX in hardware.

### OP-TEE Simulation

OP-TEE simulation mode compiles your enclave against a set of in-process
libraries that simulate the subset of the functionality that is required from
OP-TEE, including ECALL and OCALL support. This is intended to serve as a quick
verification of your code to decrease turn-around time. No hardware environment
is emulated.

To build using OP-TEE Simulation, build using the `x86-ARMTZ-Simulation-Debug`
configuration. To launch a host app associated with the enclave you wish to
debug, pick it from the list of targets next to configuration drop-down in
Visual Studio and click the run button. Alternately, use the options under the
Debug menu.

# Next Steps

Now that you have built the SDK and sample, you can either run the samples, or
jump into creating your own enclave:

* [Running the Sample EchoSockets](sample_sockets.md#sgx)
* [Developing your own enclave](new_platform_dev.md)
