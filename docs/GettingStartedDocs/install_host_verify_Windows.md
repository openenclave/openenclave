# Install the Open Enclave Host-Verify SDK NuGet Package

## Platform requirements

- Windows 10, Server 2016 or Server 2019

## Software Prerequisites

### Microsoft Visual Studio Build Tools 2019

Install [Visual Studio Build Tools 2019](https://aka.ms/vs/16/release/vs_buildtools.exe). Choose the "C++ build tools" workload. Visual Studio Build Tools 2019 has support for CMake Version 3.15 (CMake ver 3.12 or above is required for building Open Enclave Host-Verify SDK). For more information about CMake support, look [here](https://blogs.msdn.microsoft.com/vcblog/2016/10/05/cmake-support-in-visual-studio/).

### Git for Windows 64-bit

Download [Git for Windows 64-bit](https://git-scm.com/download/win).

Install Git and add Git Bash to the PATH environment variable.
Typically, Git Bash is located in `C:\Program Files\Git\bin`.
Currently the Open Enclave Host-Verify SDK build system uses bash scripts to configure
and build Linux-based 3rd-party libraries.

Open a command prompt and ensure that Git Bash is added to PATH.

```cmd
C:\>where bash
C:\Program Files\Git\bin\bash.exe
```

Tools available in the Git bash environment are also used for test and sample
builds. For example, OpenSSL is used to generate test certificates, so it is
also useful to have the `Git\mingw64\bin` folder added to PATH. This can be checked
from the command prompt as well:

```cmd
C:\>where openssl
C:\Program Files\Git\mingw64\bin\openssl.exe
```

### Clang

Download [Clang/LLVM for Windows 64-bit](http://releases.llvm.org/7.0.1/LLVM-7.0.1-win64.exe).
Install Clang 7.0.1 and add the LLVM folder (typically C:\Program Files\LLVM\bin)
to PATH. Open Enclave Host-Verify SDK uses clang to build the enclave binaries.

Open up a command prompt and ensure that clang is added to PATH.

```cmd
C:\> where clang
C:\Program Files\LLVM\bin\clang.exe
C:\> where llvm-ar
C:\Program Files\LLVM\bin\llvm-ar.exe
C:\> where ld.lld
C:\Program Files\LLVM\bin\ld.lld.exe
```

## Download and install the Azure DCAP NuGet Package

Download the required Azure DCAP NuGet Package from [here](https://github.com/microsoft/Azure-DCAP-Client/releases/latest) and place it in a directory of your choice. Use the command below to install the NuGet package with the [NuGet Command-Line Interface (CLI) tool](https://dist.nuget.org/win-x86-commandline/latest/nuget.exe). In this example, we are placing the NuGet Package in `C:\azure_dcap_nuget` and installing it to `C:\azure_dcap`.

```cmd
 nuget.exe install Microsoft.Azure.DCAP -Source C:\azure_dcap_nuget -OutputDirectory C:\azure_dcap -ExcludeVersion
```

Once installed, Azure DCAP binary is located in `C:\azure_dcap\Microsoft.Azure.DCAP\build\native`.
Azure DCAP binary is needed to provide Azure DCAP verification service. Add the folder to PATH and open a command prompt and ensure that it's added to PATH.

```cmd
c:\>where dcap_quoteprov.dll
c:\azure_dcap\Microsoft.Azure.DCAP\build\native\dcap_quoteprov.dll
```

## Download and install the Open Enclave Host-Verify SDK NuGet Package

Download the required Windows NuGet Package from [here](https://github.com/openenclave/openenclave/releases) and place them in a directory of your choice. Enter the directory where you place the NuGet CLI tool, and use the command below to install the NuGet package. In this example, we are placing the NuGet Package in `C:\openenclave_nuget` and installing it to `C:\oe`.

```cmd
 nuget.exe install open-enclave.OEHOSTVERIFY -Source C:\openenclave_nuget -OutputDirectory C:\oe -ExcludeVersion
```

Note: If it is an RC package, append `-pre` to the command above.

After the installation, the Open Enclave Host-Verify SDK will be placed in the path `C:\oe\open-enclave.OEHOSTVERIFY\openenclave`.
Use the following command to copy the SDK to `C:\openenclave`.

```cmd
xcopy /E  C:\oe\open-enclave.OEHOSTVERIFY\openenclave C:\openenclave\
```

Alternatively, we can use NuGet Package Manager to install Open Enclave Host-Verify SDK. Click [here](https://docs.microsoft.com/en-us/nuget/quickstart/install-and-use-a-package-in-visual-studio) for more information on installing and using a NuGet package in Visual Studio.

The rest of the documentation assumes `C:\openenclave` as the default installation path of the SDK.


## Verify the Open Enclave Host-Verify SDK installation

See [Using the Open Enclave Host-Verify SDK](Windows_using_host_verify.md) for verifying and using the installed SDK.
