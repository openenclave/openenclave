# Using Visual Studio to Develop Enclave Applications for Windows

This walkthrough assumes that you are using Visual Studio on a Windows development
machine, and want to develop enclaves for Windows.  If you instead want to use Visual
Studio Code, see the
[VS Code instructions](https://github.com/openenclave/openenclave/blob/master/devex/vscode-extension/README.md).

## Prerequisites

You will need the following:

- A development machine with support for SGX1 or SGX1 with Flexible Launch Control (FLC) (see [instructions for determining the SGX support level](https://github.com/microsoft/openenclave/blob/master/docs/GettingStartedDocs/SGXSupportLevel.md) if needed).
  - If you would like to install the Open Enclave Host-Verify SDK and build evidence verification applications without enclaves, then this is not necessary. For more information about the Open Enclave Host-Verify SDK, see the [installation instructions](https://github.com/microsoft/openenclave/blob/master/docs/GettingStartedDocs/install_host_verify_Windows.md).
- Visual Studio 2019, v16.5 or later
  (Community edition, or any other edition) with the "Desktop development
  with C++" workload
- NuGet Package Manager feature, installable via Tools -> Get Tools and Features... ->
  Individual components -> Code tools -> NuGet Package Manager (this should
  be already installed by the previous step above)
- [Open Enclave Wizard - Preview](https://marketplace.visualstudio.com/items?itemName=MS-TCPS.OpenEnclaveSDK-VSIX)
  Visual Studio extension, v0.7 or later.  The extension can be installed via that marketplace link, or from within
  Visual Studio.  (Do Extensions -> Manage Extensions -> Online -> search for "enclave".)  You must restart Visual Studio after
  installing the extension.
- Intel's PSW2.6. This should be automatically installed on Windows 10 systems that support SGX.  If manual install is needed:
  - For systems with support for SGX1: [Intel's PSW 2.6,Intel Enclave Common API library](https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/Contributors/WindowsManualSGX1Prereqs.md)
  - For systems with support for SGX1+FLC: [Intel's PSW2.6, Intel's Data Center Attestation Primitives and related dependencies](https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/Contributors/WindowsManualSGX1FLCDCAPPrereqs.md)
- [Clang/LLVM for Windows 64-bit](http://releases.llvm.org/7.0.1/LLVM-7.0.1-win64.exe).  The installer will ask whether LLVM should be added to the PATH, and this must be done at least for the current user, so Visual Studio can find it.

## Walkthrough: Creating a C/C++ Enclave Application

We will now walk through the process of creating a C/C++ application that uses an enclave.

1. Create a new Windows application using File -> New -> Project and find the Windows console
   app template, which
   is called "Console App" (note: NOT the "Console App (.NET Core)").
   Give the project a name, ConsoleApplication1 for example.  This will create a "Hello World" console application.
   Alternatively, if you already have such a Windows application using a Visual Studio project
   file (.vcxproj file), you can start from your existing application.
2. Create an enclave library project by right clicking on the solution in the Solution Explorer
   and selecting Add -> New Project -> Open Enclave TEE Project (Windows).  Give it a name,
   MyEnclave1 for example.  This will create a sample enclave with an `ecall_DoWorkInEnclave()`
   method exposed to applications, that will simply call an `ocall_DoWorkInHost()` method that
   will be implemented in the application.   In this walkthrough, we'll leave this project
   as is for now, but afterwards you can modify it as you like.
3. Import the enclave into your application project, by right clicking on the application
   project in the Solution Explorer and selecting Open Enclave Configuration -> Import Enclave,
   then navigate to and select the EDL file (_YourEnclaveProjectName_.edl) in your enclave project.
   This step will modify your application project settings and add some additional files to it,
   including a C file named _YourEnclaveProjectName_\_host.c.  This C file contains a
   `sample_enclave_call()` method that will load and call
   `ecall_DoWorkInEnclave()`, and also contains a sample implementation of an `ocall_DoWorkInHost()`
   method that just prints a message when called.  Although the app could be compiled and run
   at this point, `sample_enclave_call()` is still not called from anywhere.
4. Open the application's main source file (e.g., ConsoleApplication1.cpp) or if you are starting from another existing application,
   whatever file you want to invoke enclave code from. Add a call to `sample_enclave_call()`.
   For example, update the main.cpp file to look like this, where the extern C declaration is needed
   because ConsoleApplication1.cpp is a C++ file whereas the _YourEnclaveProjectName_\_host.c file is a C file:
```C
#include <iosteam>

extern "C" {
    void sample_enclave_call(void);
};

int main()
{
    std::cout << "Hello World!\n";
    sample_enclave_call();
}
```
5. For the platform, use x64, since Open Enclave currently only supports 64-bit enclaves.
6. You can now set breakpoints in Visual Studio, e.g., inside `ecall_DoWorkInEnclave()` and inside
   `ocall_DoWorkInHost()` and run and debug the enclave application just like any other application.

The solution will have two configurations: Debug and Release.

## Modifying the application

Once you have the basic application working, you can modify it as desired.  For example, to
define new APIs between the enclave and the application:

1. Edit the _YourProjectName_.edl file. Define any trusted APIs (called "ECALLs") you
   want to call from your application in the trusted{} section, and in the untrusted{}
   section, define any application APIs (called "OCALLs") that you want to call from
   your enclave.  Definitions must be described using the
   [EDL file syntax](https://software.intel.com/en-us/sgx-sdk-dev-reference-enclave-definition-language-file-syntax).
2. Edit the _YourProjectName_\_ecalls.c file, and fill in implementations of the ECALL(s) you added.
3. Edit your application sources and fill in implementations of the OCALL(s) you added.

## Known Issues

- Building Trusted Applications for TrustZone is not yet supported in this
  version.  Preview support using an earlier experimental version of the Open Enclave SDK was discussed in
  [earlier VS extension notes](https://github.com/openenclave/openenclave/blob/feature.new_platforms/new_platforms/docs/VisualStudioWindows.md).
