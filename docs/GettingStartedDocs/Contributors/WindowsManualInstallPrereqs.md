# Manually Installing Open Enclave Prerequisites for Windows on a System which supports SGX

## Platform requirements
- A system with support for SGX1 or SGX1 with Flexible Launch Control (FLC).

 Note: To check if your system has support for SGX1 with or without FLC, please look [here](../SGXSupportLevel.md).
 
- A version of Windows OS with native support for SGX features:
   - For server: Windows Server 2016 or 2019
   - For client: Windows 10 64-bit version 1709 or newer
   - To check your Windows version, run `winver` on the command line.

## Software prerequisites
- [Microsoft Visual Studio Build Tools 2019](https://aka.ms/vs/15/release/vs_buildtools.exe)
- [Git for Windows 64-bit](https://git-scm.com/download/win)
- [Clang/LLVM for Windows 64-bit](http://releases.llvm.org/7.0.1/LLVM-7.0.1-win64.exe)
- [Python 3](https://www.python.org/downloads/windows/)
- [ShellCheck](https://oejenkins.blob.core.windows.net/oejenkins/shellcheck-v0.7.0.zip)
- [OpenSSL 1.1.1](https://slproweb.com/products/Win32OpenSSL.html)
- [cmake format](https://github.com/cheshirekow/cmake_format)

## Prerequisites specific to SGX support on your system

For systems with support for SGX1  - [Intel's PSW, Intel Enclave Common API library](WindowsManualSGX1Prereqs.md)

For systems with support for SGX1 + FLC - [Intel's PSW, Intel's Data Center Attestation Primitives and related dependencies](WindowsManualSGX1FLCDCAPPrereqs.md)

## Microsoft Visual Studio Build Tools 2019
Install [Visual Studio Build Tools 2019](https://aka.ms/vs/16/release/vs_buildtools.exe). Choose the "C++ build tools" workload. Visual Studio Build Tools 2019 has support for CMake Version 3.15 (CMake ver 3.12 or above is required for building Open Enclave SDK). For more information about CMake support, look [here](https://blogs.msdn.microsoft.com/vcblog/2016/10/05/cmake-support-in-visual-studio/).

## Git for Windows 64-bit

Install Git and add Git Bash to the PATH environment variable.
Typically, Git Bash is located in `C:\Program Files\Git\bin`.
Currently the Open Enclave SDK build system uses bash scripts to configure
and build Linux-based 3rd-party libraries.

Open a command prompt and ensure that Git Bash is added to PATH.

```cmd
C:\>where bash
C:\Program Files\Git\bin\bash.exe
```

Tools available in the Git bash environment are also used for test and sample
builds. It is also useful to have the `Git\mingw64\bin` folder added to PATH.

## Clang

Install Clang 7.0.1 and add the LLVM folder (typically C:\Program Files\LLVM\bin)
to PATH. Open Enclave SDK uses clang to build the enclave binaries.

Open up a command prompt and ensure that clang is added to PATH.

```cmd
C:\> where clang
C:\Program Files\LLVM\bin\clang.exe
C:\> where llvm-ar
C:\Program Files\LLVM\bin\llvm-ar.exe
C:\> where ld.lld
C:\Program Files\LLVM\bin\ld.lld.exe
```

## Python 3

Install [Python 3 for Windows](https://www.python.org/downloads/windows/) and ensure that python.exe is available in your PATH.
Make sure the checkbox for PIP is checked when installing.

Python 3 is used as part of the mbedtls tests and for cmake-format.

## ShellCheck

[ShellCheck](https://www.shellcheck.net/) is used to check the format of shell scripts. Install it as follows.

Download the [ShellCheck zip](https://oejenkins.blob.core.windows.net/oejenkins/shellcheck-v0.7.0.zip).
Inside it there is a shellcheck-v0.7.0.exe which must be copied to a directory in your PATH and renamed to shellcheck.exe.

## OpenSSL

Download and install the latest [Win64 OpenSSL 1.1.1](https://slproweb.com/products/Win32OpenSSL.html). Do not choose the light version; for example, use Win64OpenSSL-1_1_1g.exe, not Win64OpenSSL_Light-1_1_1g.exe.

## cmake format

Install `cmake-format` as follows.

```cmd
pip install cmake_format
```

Open up a command prompt and ensure that `cmake-format` is added to the `PATH`.

```cmd
C:\Users\test> where cmake-format
C:\Users\test\AppData\Local\Programs\Python\Python37-32\Scripts\cmake-format.exe
```
