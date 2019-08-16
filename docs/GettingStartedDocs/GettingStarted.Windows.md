Getting Started on Windows [Work in progress]
=========================================

Introduction
------------

This document is a work in progress. It describes how to use experimental
support in the Open Enclave SDK to build Windows host applications that can
load ELF enclaves built using clang.

Please refer to the following [documentation](/docs/GettingStartedDocs/SGXSupportLevel.md) to determine the SGX support level for your target system. The instructions below work for systems with SGX1+FLC support. Instructions for systems with SGX1 but no FLC support are coming soon. 

'Simulator' mode is not available in Windows.

Prerequisites
-------------

The following are prerequisites for building and running Open Enclave on
Windows.

- Intel® X86-64bit architecture with SGX1 or SGX2
- A version of Windows OS with native support for SGX features:
   - For server: Windows Server 2016 (or newer)
   - For client: Windows 10 64-bit with Fall Creators Update (1709) or newer
- [Intel® SGX Platform Software for Windows (PSW)](
  https://software.intel.com/sites/default/files/managed/0f/c8/Intel-SGX-PSW-Release-Notes-for-Windows-OS.pdf)
- [Microsoft Visual Studio 2017](https://visualstudio.microsoft.com/vs/older-downloads/)
- [Git for Windows 64-bit](https://git-scm.com/download/win)
- [OCaml for Windows 64-bit](https://www.ocamlpro.com/pub/ocpwin/ocpwin-builds/ocpwin64/20160113/)
- [Clang/LLVM for Windows 64-bit](http://releases.llvm.org/7.0.1/LLVM-7.0.1-win64.exe)

To deploy all the prerequisities for building Open Enclave, you can run the ```scripts/install-windows-prereqs.ps1```

```powershell
cd scripts
.\install-windows-prereqs.ps1
```

To deploy each prerequisite individually, refer to the sections below.

Intel® SGX Platform Software for Windows (PSW)
---------------------------------

The PSW should be installed automatically on Windows 10 with the Fall Creators
Update installed, or on a Windows Server 2016 image for an Azure Confidential
Compute VM. You can verify that is the case on the command line as follows:

```cmd
sc query aesmservice
```

The state of the service should be "running" (4). Follow Intel's documentation for troubleshooting.

Note that Open Enclave is only compatible with the Intel PSW 2.2.
To use Intel PSW 2.3 and higher, please refer _Building with Intel Data Center Attestation
Primitives (DCAP) libraries_ below.

Microsoft Visual Studio 2017
---------------------------------
Install [Microsoft Visual Studio 2017](https://visualstudio.microsoft.com/vs/older-downloads/).
Visual Studio 2017's CMake support (ver 3.12 or above) is required for building the Open Enclave SDK.
Note cmake in Visual Studio 2019 is not fully supported yet.
For more information about cmake support, refer to
https://blogs.msdn.microsoft.com/vcblog/2016/10/05/cmake-support-in-visual-studio/

Git for Windows 64-bit
---------------------------------
Install Git and add Git's bash to the path.
Typically, Git's bash is located in C:\Program Files\Git\bin.
Currently the Open Enclave SDK build system uses bash scripts to configure
and build Linux-based 3rd-party libraries.

Open a command prompt and ensure that bash is available in the path:
```cmd
C:\>where bash
C:\Program Files\Git\bin\bash.exe
```

Tools available in the Git bash environment are also used for test and sample
builds. For example, OpenSSL is used to generate test certificates, so it is
also useful to have the `Git\mingw64\bin` folder pathed. This can be checked
from the command prompt as well:

```cmd
C:\>where openssl
C:\Program Files\Git\mingw64\bin\openssl.exe
```

Clang
---------------------------------
Install Clang 7.0.1 and add the LLVM folder (typically C:\Program Files\LLVM\bin)
to the path. Open Enclave SDK uses clang to build the enclave binaries.

Open up a command prompt and ensure that clang is available in the path:
```cmd
C:\> where clang
C:\Program Files\LLVM\bin\clang.exe
C:\> where llvm-ar
C:\Program Files\LLVM\bin\llvm-ar.exe
C:\> where ld.lld
C:\Program Files\LLVM\bin\ld.lld.exe
```

OCaml
---------------------------------
Install [OCaml for Windows (64-bit)](https://www.ocamlpro.com/pub/ocpwin/ocpwin-builds/ocpwin64/20160113/).
Please download and install the mingw64 exe for OCaml, for example, https://www.ocamlpro.com/pub/ocpwin/ocpwin-builds/ocpwin64/20160113/ocpwin64-20160113-4.02.1+ocp1-mingw64.exe.

[Alternate OCaml Web-site](https://fdopen.github.io/opam-repository-mingw/installation/)

OCaml is used to build the oeedger8r tool as part of the OE SDK.

Open up a command prompt and ensure that ocaml is available in the path:
```cmd
C:\> where ocaml
C:\Program Files\ocpwin64\4.02.1+ocp1-msvc64-20160113\bin\ocaml.exe
```

Obtaining the source distribution
---------------------------------

Open Enclave is available from GitHub.

### In Visual Studio 2017:
1. Under Team > Manage Connections... > Local Git Repositories, select the Clone
   dropdown
2. Set the URL to clone as: https://github.com/openenclave/openenclave.
3. Set the local path you want to clone the repo to (e.g. C:/openenclave).
4. Click the Clone button.

### In Git shell:
```
git clone https://github.com/openenclave/openenclave
```

This creates a source tree under the directory called openenclave.

Building
--------

### Building on Windows using Visual Studio 2017
[Visual Studio 2017 has integrated support for loading CMake projects](
https://blogs.msdn.microsoft.com/vcblog/2016/10/05/cmake-support-in-visual-studio/):

1. Under the File menu, select Open > CMake...
2. Open the CMakeLists.txt at the root of your Open Enclave repo
   (e.g. C:\openenclave\CMakeLists.txt)
3. The CMake menu option should appear when it detects that a valid CMake project
   is loaded. VS2017 will then recursively walk the repo directory structure and
   generate a cache for the project to display Intellisense. This may take several minutes the first time.
4. Open Enclave is only supported for 64-bit. By default the `x64-Debug` configuration is 
   selected.
5. Once cache generation is complete, you can build the project via the CMake >
   Build All menu option.

The results of the build will be displayed in the Output window and any build
errors or warnings collated in the Error List window.

You can change the build settings with the CMake > Change CMake Settings menu
option. This opens the [CMakeSettings.json](https://blogs.msdn.microsoft.com/vcblog/2017/08/14/cmake-support-in-visual-studio-customizing-your-environment/)
file which you can edit and change settings such as the target build location.

By default, Open Enclave SDK will be built in the following location:
```
${workspaceRoot}\build\<configuration-name>
```
For example:
```
C:\openenclave\build\x64-Debug
```
### Building on Windows using Developer Command Prompt

1. Launch the [x64 Native Tools Command Prompt for VS 2017](
https://docs.microsoft.com/en-us/dotnet/framework/tools/developer-command-prompt-for-vs)
Normally this is accessible under the `Visual Studio 2017` folder in the Start Menu.

2. At the x64 Native Tools command prompt, use cmake and ninja to build the debug version:

   ```cmd
   cd C:\openenclave
   mkdir build\x64-Debug
   cd build\x64-Debug
   cmake -G Ninja -DBUILD_ENCLAVES=1 ../..
   ninja
   ```

   Similarly, build the release version with:
    ```cmd
   cd C:\openenclave
   mkdir build\x64-Release
   cd build\x64-Release
   cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_ENCLAVES=1 ../..
   ninja
   ```

### Building with Intel Data Center Attestation Primitives (DCAP) [Experimental]

#### Installing additional dependencies for DCAP
To use the Intel DCAP libraries for upcoming support for SGX attestation on Windows Server 2016,
you will need to install the following dependencies:

##### [Intel Platform Software for Windows (PSW) v2.4](http://registrationcenter-download.intel.com/akdlm/irc_nas/15654/Intel%20SGX%20PSW%20for%20Windows%20v2.4.100.51291.exe)

After unpacking the self-extracting ZIP executable, install the *PSW_EXE_RS2_and_before* version for Windows Server 2016:
```cmd
C:\Intel SGX PSW for Windows v2.3.100.49777\PSW_EXE_RS2_and_before\Intel(R)_SGX_Windows_x64_PSW_2.3.100.49777.exe
```
##### [Intel Data Center Attestation Primitives (DCAP) Libraries v1.2](http://registrationcenter-download.intel.com/akdlm/irc_nas/15650/Intel%20SGX%20DCAP%20for%20Windows%20v1.2.100.49925.exe)
After unpacking the self-extracting ZIP executable, you can refer to the *Intel SGX DCAP Windows SW Installation Guide.pdf*
for more details on how to install the contents of the package.

The following summary will assume that the contents were extracted to `C:\Intel SGX DCAP for Windows v1.2.100.49925`:

1. Unzip the required drivers from the extracted subfolders:
    - `LC_driver_WinServer2016\Signed_1152921504628095185.zip`
    - `DCAP_INF\WinServer2016\Signed_1152921504628099289.zip`

   The following instructions will assume that these have been unzipped into the `LC_driver` and `DCAP_INF` folders respectively.

2. Allow the SGX Launch Configuration driver (LC_driver) to run:
    - From an elevated command prompt:
      ```cmd
      reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sgx_lc_msr\Parameters /v "SGX_Launch_Config_Optin" /t REG_DWORD /d 1
      reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sgx_lc_msr\Parameters /v "SGX_Launch_Config_Optin"
      ```
    - If the driver is already installed and running, the machine will need to be rebooted for the change to take effect.

3. Install the drivers:
    - `devcon.exe` from the [Windows Driver Kit for Windows 10](https://go.microsoft.com/fwlink/?linkid=2026156)
      can be used to install the drivers from an elevated command prompt:
      ```cmd
      devcon.exe install LC_driver\drivers\b361e4d8-bc01-43fc-b8a6-8d101e659ed1\sgx_base_dev.inf root\SgxLCDevice
      devcon.exe install DCAP_INF\drivers\226fdf07-49d3-46aa-a0ce-f21b6d4a05cf\sgx_dcap_dev.inf root\SgxLCDevice_DCAP
      ```
    - Note that `devcon.exe` is usually installed to `C:\Program Files (x86)\Windows Kits\10\tools\x64` and is *not* pathed by default.

4. Install the DCAP nuget packages:
    - The standalone `nuget.exe` [CLI tool](https://dist.nuget.org/win-x86-commandline/latest/nuget.exe) can be used to do this from the command prompt:
      ```cmd
      nuget.exe install DCAP_Components -ExcludeVersion -Source "C:\Intel SGX DCAP for Windows v1.2.100.49925\nuget" -OutputDirectory C\openenclave\prereqs\nuget
      nuget.exe install EnclaveCommonAPI -ExcludeVersion -Source "C:\Intel SGX DCAP for Windows v1.2.100.49925\nuget" -OutputDirectory C:\openenclave\prereqs\nuget
      ```
    - *Note:* EnclaveCommonAPI should be installed as the *very last* nuget package as a temporary workaround for a dependency issue.

##### [Azure DCAP client for Windows](https://github.com/Microsoft/Azure-DCAP-Client/tree/master/src/Windows) [optional]

Integration with the Azure DCAP client is not yet enabled on Windows in Open Enclave, and the Microsoft.Azure.DCAP.Client.1.0.0.nupkg
is not yet available as a binary drop.

For experimental purposes, it can be built from sources using [instructions](https://github.com/microsoft/Azure-DCAP-Client/blob/master/src/Windows/README.MD)
on the GitHub repo:

- The Azure DCAP Client has a build dependency on version 17134 of the Windows 10 SDK.
   - This can be added via the Visual Studio Installer under Individual Components > Windows 10 SDK (10.0.17134.0).

- Assuming the resulting .nupkg is put into the `C:\Azure-DCAP-Client` folder, it can be installed using:
  ```cmd
  nuget.exe install Microsoft.Azure.DCAP.Client -ExcludeVersion -Source "C:\Azure-DCAP-Client;nuget.org" -OutputDirectory C:\openenclave\prereqs\nuget
  ```

  Note the inclusion of `nuget.org` as one of the sources. This is necessary because Azure DCAP Client
  has a dependency on curl and this allows `nuget.exe` to install the curl package dependency tree at the
  same time. This includes:
    - curl
    - curl.redist
    - libssh2
    - libssh2.redist
    - openssl
    - openssl.redist
    - zlib
    - zlib.redist

- The [Visual C++ Redistributable for Visual Studio 2012](https://www.microsoft.com/en-us/download/confirmation.aspx?id=30679&6B49FDFB-8E5B-4B07-BC31-15695C5A2143=1) will also need to be installed to provide MSVCR110.dll for the Release build of curl.
  - The redistributable install does not include MSVCR110d.dll needed for the Debug version of curl.

#### Building with DCAP libraries using Visual Studio 2017
To build with the DCAP libraries in Visual Studio, you will need to add the
`-DUSE_LIBSGX=1` to `cmakeCommandArgs` in the CMakeSettings.json file for each of the
configurations you want to build with it.

For example, to enable it for x64-Debug, do this in your json file:

```json
  "configurations": [
    {
      "name": "x64-Debug",
      "generator": "Ninja",
      "configurationType": "Debug",
      "inheritEnvironments": [ "msvc_x64_x64" ],
      "buildRoot": "${workspaceRoot}\\build\\x64-Debug",
      "installRoot": "${env.USERPROFILE}\\CMakeBuilds\\${workspaceHash}\\install\\${name}",
      "cmakeCommandArgs": "-DBUILD_ENCLAVES=1 -DUSE_LIBSGX=1",
      "buildCommandArgs": "-v",
      "ctestCommandArgs": ""
    },
```

The CMake > Build All menu option will work as usual once this is configured.

#### Building with DCAP libraries using Developer Command Prompt

To build with the DCAP libraries in the x64 Native Tools Command Prompt for VS 2017,
just add the `-DUSE_LIBSGX=1` option to the `cmake` call before starting the `ninja`
build. For example, for the x64-Debug configuration:

```cmd
cd C:\openenclave
mkdir build\x64-Debug
cd build\x64-Debug
cmake -G Ninja -DBUILD_ENCLAVES=1 -DUSE_LIBSGX=1 ../..
ninja
```

Testing
-------

Note that the use of Simulation Mode via the `OE_SIMULATION` flag is _not_ supported on Windows.
See [#1753](https://github.com/openenclave/openenclave/issues/1753) for details.

### Running tests in Visual Studio 2017

1. Open the CMake project in Visual Studio from menu File > Open > CMake...
   and select top level CMakeLists.txt file which is present in openenclave folder.
2. Select menu CMake > Tests > Run Open Enclave SDK CTests.

### Running tests on the Developer Command Prompt
On the x64 Native Tools Command Prompt for VS 2017:

```cmd
ctest
```

Known Issues
------------
* Samples have not yet been ported to Windows
* Not all tests currently run on Windows. See tests/CMakeLists.txt for a list of supported tests.
