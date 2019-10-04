# Building Open Enclave SDK Samples on Windows

All the samples that come with the Open Enclave SDK installation share similar directory structure and build instructions. The section contains general information on how to setup/build/sign/run all samples. It's important that you read information on this page before jumping into any individual sample.

## Common Sample information

### How Sample source code directories were structured

Open Enclave SDK helps developers build enclave applications. An enclave application is partitioned into an untrusted component (called a host) and a trusted component (called an enclave). An enclave is a secure container whose memory (text and data) is protected from access by outside entities, including the host, privileged users, and even the hardware. All functionality that needs to be run in a Trusted Execution Environment (TEE) should be compiled into the enclave binary. The enclave may run in an untrusted environment with the expectation that secrets will not be compromised. A host is a normal user mode application that loads an enclave into its address space before starting interacting with an enclave. 

![Sample components diagram](sampledirstructure.png)

All the samples that come with the Open Enclave SDK installation are all structured into two subdirectories (one for enclave and one for host) accordingly.

| Files/dir        |  contents                                   |
|:-----------------|---------------------------------------------|
| enclave        | Files needed for building the sample enclave|
| host           | Files needed for building the host          |

### Prepare samples

Building samples involves writing files into the working directory. You can do this in the directory in which you have installed your samples.
You can also copy the samples from the location they were installed to another directory.

```cmd
xcopy  C:\openenclave\share\openenclave\samples C:\mysample
```

## Install the prerequisites

### Platform requirements

- A system with support for SGX1 or SGX1 with Flexible Launch Control (FLC).

 Note: To check if your system has support for SGX1 with or without FLC, please look [here](https://github.com/openenclave/openenclave/tree/master/docs/GettingStartedDocs/SGXSupportLevel.md).
 
- A version of Windows OS with native support for SGX features:
   - For server: Windows Server 2016
   - For client: Windows 10 64-bit version 1709 or newer
   - To check your Windows version, run `winver` on the command line.

### Software prerequisites

- [Microsoft Visual Studio Build Tools 2019](https://aka.ms/vs/15/release/vs_buildtools.exe)
- [Clang/LLVM for Windows 64-bit](http://releases.llvm.org/7.0.1/LLVM-7.0.1-win64.exe)
- [OpenSSL 1.1.1d](https://slproweb.com/download/Win64OpenSSL-1_1_1d.exe)

### Prerequisites specific to SGX support on your system

For systems with support for SGX1  - [Intel's PSW 2.2](https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/Contributors/WindowsManualSGX1Prereqs.md)

For systems with support for SGX1 + FLC - [Intel's PSW 2.4, Intel's Data Center Attestation Primitives and related dependencies](https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/Contributors/WindowsManualSGX1FLCDCAPPrereqs.md)

## Microsoft Visual Studio Build Tools 2019
Install [Visual Studio Build Tools 2019](https://aka.ms/vs/16/release/vs_buildtools.exe). Choose the " C++ build tools" workload. Visual Studio Build Tools 2019has support for CMake Version 3.15 (CMake ver 3.12 or above is required for building Open Enclave SDK). For more information about CMake support, look [here](https://blogs.msdn.microsoft.com/vcblog/2016/10/05/cmake-support-in-visual-studio/).

### Clang

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

### OpenSSL

Install OpenSSL and add the bin directory to PATH.

### How to build and run samples

1. Launch the [x64 Native Tools Command Prompt for VS 2017](
https://docs.microsoft.com/en-us/dotnet/framework/tools/developer-command-prompt-for-vs)
Normally this is accessible under the `Visual Studio 2017` folder in the Start Menu.

2. Set OpenEnclave_DIR to the cmake directory in the Open Enclave SDK installation. 

As an example, if the Open Enclave SDK is installed to `C:\openenclave`, then you would set OpenEnclaveDIR as shown below

```cmd
set OpenEnclaveDIR=C:\openenclave\lib\openenclave\cmake
```

3. To build a sample using CMake, change directory to your target sample directory and execute the following commands:

```cmd
mkdir build
cd build
cmake .. -G Ninja -DNUGET_PACKAGE_PATH=C:/your/path/to/intel_nuget_packages
ninja
```

4. To run the sample, use below:

```cmd
ninja run
```

## Samples

The following samples demonstrate how to develop enclave applications using OE APIs. It's recommended to go through the following samples in the order listed.

#### [HelloWorld](helloworld/README.md)

- Minimum code needed for an OE app
- Help understand the basic components an OE application
- Demonstrate how to build, sign, and run an OE image

#### [File-Encryptor](file-encryptor/README.md)

- Shows how to encrypt and decrypt data inside an enclave
- Uses AES mbedTLS API to perform encryption and decryption

#### [Data-Sealing](data-sealing/README.md)

- Introduce OE sealing and unsealing features 
- Demonstrate how to use OE sealing APIs
- Explore two supported seal polices
  - OE_SEAL_POLICY_UNIQUE
  - OE_SEAL_POLICY_PRODUCT

#### [Remote Attestation](remote_attestation/README.md)

- Explain how OE attestation works
- Demonstrate an implementation of remote attestation between two enclaves running on different machines

#### [Local Attestation](local_attestation/README.md)

- Explain the concept of OE local attestation
- Demonstrate an implementation of local attestation between two enclaves on the same VM

#### [Switchless Calls](switchless/README.md)

- Explain the concept of switchless calls
- Identify cases where switchless calls are appropriate
- Demonstrate how to mark a function as `transition_using_threads` in EDL
- Demonstrate how to configure an enclave to enable switchless calls originated within it
- Recommend the number of host worker threads required for switchless calls in practice
- Demonstrate how to enable switchless calls in an enclave application
