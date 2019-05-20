Getting Started on Windows [Work in progress]
=========================================

Introduction
------------

This document is a work in progress. It describes how to use experimental
support in the Open Enclave SDK to build Windows host applications that can
load ELF enclaves built using clang.

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

Intel® SGX Platform Software for Windows (PSW)
---------------------------------

The PSW should be installed automatically on Windows 10 with the Fall Creators
Update installed, or on a Windows Server 2016 image for an Azure Confidential
Compute VM. You can verify that is the case on the command line as follows:

```cmd
sc query aesmservice
```

The state of the service should be "running" (4). Follow Intel's documentation for troubleshooting.

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
and process few 3rd-party libraries.

Open a command prompt and ensure that bash is available in the path:
```cmd
C:\>where bash
C:\Program Files\Git\bin\bash.exe
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
2. Set the URL to clone as: https://github.com/Microsoft/openenclave.
3. Set the local path you want to clone the repo to (e.g. C:/openenclave).
4. Click the Clone button.

### In Git shell:
```
git clone https://github.com/Microsoft/openenclave
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

Testing
-------

### Running ctests in Visual Studio 2017

How to build the CMake project using Visual Studio 2017
--------------------------------------------------------
1. Open CMake project in Visual Studio from menu File > Open > CMake...
   and select top level CMakeLists.txt file which is present in openenclave folder.
2. Select menu CMake > Tests > Run Open Enclave SDK CTests.

### Running ctests on the command line
At the x64 Native Tools command prompt do: 

```cmd
ctest
```

Known Issues
------------
* Samples have not yet been ported to Windows
* Not all tests currently run on Windows. See See tests/CMakeLists for a list of supported tests.  
* Simulation mode is disabled on Windows due to issue [#1753](https://github.com/microsoft/openenclave/issues/1753).
  ```