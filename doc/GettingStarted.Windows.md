Getting Started on Windows [Experimental]
=========================================

Introduction
------------

This document is a work in progress. It describes how to use experimental
support in the Open Enclave SDK to build Windows host applications that can
load enclaves built on Linux.

You will need to be familiar with how to use the Open Enclave SDK on Linux,
as you will need to set up a Linux build environment with which to build
then enclave binaries. That information, along with a step-by-step tutorial
on building an enclave application, is covered in [Getting Started with
Open Enclave](GettingStarted.md) document.

Prerequisites
-------------

The following are prerequisites for building and running Open Enclave on
Windows.

- Intel® X86-64bit architecture with SGX1 or SGX2
- Windows 10 64-bit with Fall Creators Update (1709)
- [Intel® SGX Platform Software for Windows (PSW)](
  https://software.intel.com/sites/default/files/managed/0f/c8/Intel-SGX-PSW-Release-Notes-for-Windows-OS.pdf)

The PSW should be installed automatically on Windows 10 with the Fall Creators
Update installed. You can verify that is the case on the command line as
follows:

```
C:\> sc query aesmservice
```

The state of the service should be "running" (4). See the Troubleshooting
section on how to manually install the PSW if it is not installed.

In addition, you will need to set up a development environment to build both the
Linux and Windows binaries:

- [Windows Subsystem for Linux (WSL)](
  https://docs.microsoft.com/en-us/windows/wsl/install-win10)
- [Microsoft Visual Studio 2017](https://www.visualstudio.com/downloads/)
  - [Windows 10 SDK (10.0.16299)](
    https://developer.microsoft.com/en-US/windows/downloads/windows-10-sdk)
- [Git for Windows 64-bit](https://git-scm.com/download/win)
- [CMake 3.5.1+](https://cmake.org/download/)


Obtaining the source distribution
---------------------------------

Open Enclave is available from GitHub.

### In Visual Studio 2017:
1. Under Team > Manage Connections... > Local Git Repositories, select the Clone
   dropdown
2. Set the clone URL to https://github.com/Microsoft/openenclave and optionally
   the local path you want to clone the repo to.
3. Click the Clone button.

### In Git shell:
```
C:\> git clone https://github.com/Microsoft/openenclave
```

This creates a source tree under the directory called openenclave.

Building
--------

### Building on Linux
Host applications can be built on Windows but enclaves cannot, so enclaves
must be built on Linux and then copied to Windows for testing. The [instructions
for setting up a Linux development environment](GettingStarted.md) are
applicable to WSL as well.

To summarize, assuming your local Open Enclave repo is at C:\openenclave, it can
be built in the WSL shell using:
```
$ cd /mnt/c/openenclave
$ mkdir build
$ cd build
$ cmake ..
$ make
```

### Building on Windows using Visual Studio 2017
[Visual Studio 2017 has integrated support for loading CMake projects](
https://blogs.msdn.microsoft.com/vcblog/2016/10/05/cmake-support-in-visual-studio/):

1. Under the File menu, select Open > CMake...
2. Open the CMakeLists.txt at the root of your Open Enclave repo
   (e.g. C:\openenclave\CMakeLists.txt)
3. The CMake menu option should appear when it detects a valid CMake project is
   loaded. VS2017 will then recursively walk the repo directory structure and
   generate a cache for the project to display Intellisense.
4. Open Enclave is only supported for 64-bit, so change the build flavor to
   `x64-Debug`
  a. You may need to cancel cache generation and start it again after changing
     the build flavor.
5. Once cache generation is complete, you can build the project via the CMake >
   Build All menu option.

The results of the build will be displayed in the Output window and any build
errors or warnings collated in the Error List window.

You can change the build settings by with the CMake > Change CMake Settings menu
option. This opens the [CMakeSettings.json](https://blogs.msdn.microsoft.com/vcblog/2017/08/14/cmake-support-in-visual-studio-customizing-your-environment/)
file which you can edit and change settings such as the target build location.

By default, VS2017 will build to a dynamically generated folder name:
```
${env.USERPROFILE}\CMakeBuilds\\${workspaceHash}\\build\\${name}
```
For example:
```
C:\Users\username\CMakeBuilds\ca6d6e50-e70d-c836-ac64-910bf7e68090\build\x64-Debug
```

### Building on Windows using Developer Command Prompt

1. From the Start menu, launch the [Developer Command Prompt](
https://docs.microsoft.com/en-us/dotnet/framework/tools/developer-command-prompt-for-vs)
2. At the command prompt, use cmake and nmake to build the project:
   ```
   C:\> cd C:\openenclave
   C:\openenclave> mkdir build
   C:\openenclave> cd build
   C:\openenclave> cmake ..
   C:\openenclave> nmake
   ```

Alternatively, you can also try to generate a Visual Studio project using CMake
and build the resulting project instead. Again from a Developer Command Prompt:

```
C:\> cmake -G "Visual Studio 14 2015 Win64" -DENABLE_REFMAN=OFF C:\openenclave
C:\> msbuild ALL_BUILD.vcxproj
```

Testing
-------

### Running ctests in Visual Studio 2017
For now, integrated CMake support in VS2017 will only support running tests that
do not have an enclave dependency:

1. With the Open Enclave CMake project opened in VS2017, select CMake > Run
   Tests > openenclave

The Output window should indicate that `tests/mem` and `tests/str` were run.

### Running ctests on the command line
For tests that have an enclave dependency, you will need to manually copy the
enclave from the Linux build location into the same folder as the host app in
the Windows build folder. For example, to run `tests/ecall`:

```
C:\> copy C:\openenclave\build\tests\ecall\enc\ecallenc.signed.so
      C:\Users\username\CMakeBuilds\build\x64-Debug\tests\ecall\host
C:\> cd C:\Users\username\CMakeBuilds\build\x64-Debug\tests\ecall\host
C:\> ecallhost ecallenc.signed.so
```

For the moment, only `tests/echo` and `tests/ecall` can be built and run on
Windows.


Known Issues
------------

* Enclaves cannot be run under WSL outside of simulation mode.

* Ctests fail when run under WSL even when OE_SIMULATION=1. This can be avoided by
  running the ctests in a Linux VM.

Troubleshooting
---------------

### Manual install of Intel SGX PSW

1. Verify that you have Windows 10 Fall Creators Update or higher installed:
   ```
   C:\> winver
   ```
   The version should be 1709 or higher. If it is not, go to Settings > Update
   & Security > Windows Update and check for updates.

2. Get the latest releases of the Intel SGX drivers from Windows Update Catalog:
   a. Download and extract the contents of the latest [ACPI\INT0E0C package](
     http://download.windowsupdate.com/d/msdownload/update/driver/drvs/2018/01/af564f2c-2bc5-43be-a863-437a5a0008cb_61e7ba0c2e17c87caf4d5d3cdf1f35f6be462b38.cab)
   b. Download and extract the contents of the latest [VEN_INT&DEV_0E0C package](
     http://download.windowsupdate.com/d/msdownload/update/driver/drvs/2018/01/6f61d533-e985-49dd-94c7-eeab74c216b7_3f45627e8b3be2f53db09b4b209cca7ec598cc4c.cab)

3. Install the packages to the local driver store using [pnputil.exe](
   https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/pnputil):
   ```
   C:\> Pnputil.exe /add-driver <extracted path>\sgx_psw.inf
   C:\> Pnputil.exe /add-driver <extracted path>\sgx_base.inf /install
   ```

4. Check that the PSW successfully installed
   ```
   sc query aesmservice
   ```
   The service state should be "running" (4)
