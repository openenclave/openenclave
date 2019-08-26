
# Manually Installing Open Enclave Prerequisites for Windows on a System which supports SGX

## Platform requirements
- A system with support for SGX1 or SGX1 with Flexible Launch Control (FLC).
 Note: To check if your system has support for SGX1 with or without FLC, please look [here](../SGXSupportLevel.md).
 
- A version of Windows OS with native support for SGX features:
   - For server: Windows Server 2016
   - For client: Windows 10 64-bit version 1709 or newer
   - To check your Windows version, run `winver` on the command line.

## Software prerequisites
- [Microsoft Visual Studio Build Tools 2017](https://aka.ms/vs/15/release/vs_buildtools.exe)
- [Git for Windows 64-bit](https://git-scm.com/download/win)
- [OCaml for Windows 64-bit](https://www.ocamlpro.com/pub/ocpwin/ocpwin-builds/ocpwin64/20160113/)
- [Clang/LLVM for Windows 64-bit](http://releases.llvm.org/7.0.1/LLVM-7.0.1-win64.exe)

## Prerequisites specific to SGX support on your system
- For systems with support for SGX1  - [Intel's PSW 2.2](WindowsManualSGX1Prereqs.md)
- For systems with support for SGX1 + FLC - 
 [Intel's PSW 2.4, Intel's Data Center Attestation primitives and related dependencies](WindowsManualSGX1FLCDCAPPrereqs.md)

## Microsoft Visual Studio Build Tools 2017

Install [Visual Studio Build Tools 2017](https://aka.ms/vs/15/release/vs_buildtools.exe). Choose the "Visual C++ build tools" workload.
Visual Studio Build Tools 2017's CMake support (ver 3.12 or above) is required for building the Open Enclave SDK.
Note that cmake in Visual Studio 2019 is not fully supported yet.
For more information about cmake support, refer to
https://blogs.msdn.microsoft.com/vcblog/2016/10/05/cmake-support-in-visual-studio/

## Git for Windows 64-bit

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

## Clang

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

## OCaml

Install [OCaml for Windows (64-bit)](https://www.ocamlpro.com/pub/ocpwin/ocpwin-builds/ocpwin64/20160113/).
Please download and install the [mingw64 exe for OCaml](https://www.ocamlpro.com/pub/ocpwin/ocpwin-builds/ocpwin64/20160113/ocpwin64-20160113-4.02.1+ocp1-mingw64.exe).

[Alternate OCaml Web-site](https://fdopen.github.io/opam-repository-mingw/installation/)

OCaml is used to build the oeedger8r tool as part of the OE SDK.

Open up a command prompt and ensure that ocaml is available in the path:
```cmd
C:\> where ocaml
C:\Program Files\ocpwin64\4.02.1+ocp1-msvc64-20160113\bin\ocaml.exe
```