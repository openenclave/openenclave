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
- Windows 10 64-bit with Fall Creators Update (1709)
- [Intel® SGX Platform Software for Windows (PSW)](
  https://software.intel.com/sites/default/files/managed/0f/c8/Intel-SGX-PSW-Release-Notes-for-Windows-OS.pdf)
- [Microsoft Visual Studio 2017](https://www.visualstudio.com/downloads/)
- [Git for Windows 64-bit](https://git-scm.com/download/win)
- [clang (preferably version 7.0 or above)](http://releases.llvm.org/download.html)  
- [OCaml on Windows 64-bit](https://fdopen.github.io/opam-repository-mingw/installation/) (Note that this will install a Mingw environment for OCaml.)


Intel® SGX Platform Software for Windows (PSW) 
---------------------------------

The PSW should be installed automatically on Windows 10 with the Fall Creators
Update installed. You can verify that is the case on the command line as
follows:

```cmd
sc query aesmservice
```

The state of the service should be "running" (4). Follow Intel's documentation for troubleshooting.

Microsoft Visual Studio 2017
---------------------------------
Install the latest version of [Microsoft Visual Studio 2017](https://www.visualstudio.com/downloads/).
Visual Studio 2017's cmake support is required for building the Open Enclave SDK.
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
Install the latest version of Clang and add the LLVM folder (typically C:\Program Files\LLVM\bin)
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

Configuring OCaml for Windows
---------------------------------
After installing OCaml, there are a few one-time OCaml configuration steps:

1. Add `ocaml-env.exe` to the `PATH` environment variable. The default path of `ocaml-env.exe` is  `C:\OCaml64\usr\local\bin\ocaml-env.exe`.
2. Open `cmd.exe` (or another shell) and run `ocaml-env exec -- cmd.exe`. This creates a OCaml environment in the shell.
3. Install `ocamlbuild` by running `opam install ocamlbuild`.
4. Exit out of the shell.

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
C:\> git clone https://github.com/Microsoft/openenclave
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
3. The CMake menu option should appear when it detects a valid CMake project is
   loaded. VS2017 will then recursively walk the repo directory structure and
   generate a cache for the project to display Intellisense.
4. Open Enclave is only supported for 64-bit, by default the `x64-Debug` configuration is 
   selected.
5. Once cache generation is complete, you can build the project via the CMake >
   Build All menu option.

The results of the build will be displayed in the Output window and any build
errors or warnings collated in the Error List window.

You can change the build settings by with the CMake > Change CMake Settings menu
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
2. At the x64 Native Tools command prompt, use cmake and nmake to build the project:
   ```cmd
   cd C:\openenclave
   mkdir build\x64-Debug
   cd build\x64-Debug
   cmake -G Ninja -DBUILD_ENCLAVES=1 ../..
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

Simulation mode
```cmd
set OE_SIMULATION=1
ctest
```

Known Issues
------------
* Samples have not yet been ported to Windows
* Not all tests currently run on Windows. See See tests/CMakeLists for a list of supported tests.  
* The following tests are known to fail under simulation mode
  - tests/ecall (SEGFAULT)
  - tests/ecall_ocall (SEGFAULT)
  - tests/file (SEGFAULT)
  - tests/oethread (SEGFAULT)
  - tests/pthread (SEGFAULT)
  - tests/threadcxx (SEGFAULT)
  - tests/thread_local (SEGFAULT)
  - tests/thread_local_exported (SEGFAULT)
