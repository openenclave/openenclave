# Using Visual Studio to Develop Enclave Applications for Linux

This walkthrough assumes that you are using Visual Studio on a Windows development
machine, and want to develop enclaves for Linux.  If you instead want to use Visual
Studio Code on a development machine running either Windows or Linux, see the
[VS Code instructions](https://github.com/openenclave/openenclave/blob/master/devex/vscode-extension/README.md).

## Prerequisites

To install the Open Enclave Host-Verify SDK instead, see [installation instructions for Ubuntu 16.04](https://github.com/microsoft/openenclave/blob/master/docs/GettingStartedDocs/install_host_verify_Ubuntu_16.04.md) or [installation instructions for Ubuntu 18.04](https://github.com/microsoft/openenclave/blob/master/docs/GettingStartedDocs/install_host_verify_Ubuntu_18.04.md).

To develop Linux applications using a Windows development machine, you will need the following:

- [Visual Studio](https://visualstudio.microsoft.com/downloads/) 2019
  (Community edition, or any other edition)
- ["Linux development with C++" Visual Studio workload](https://devblogs.microsoft.com/cppblog/linux-development-with-c-in-visual-studio/),
  installable via Tools ->
  Workloads -> Other Toolsets -> Linux Development with C++
- NuGet Package Manager feature, installable via Tools ->
  Individual components -> Code tools -> NuGet Package Manager
- [Open Enclave Wizard - Preview](https://marketplace.visualstudio.com/items?itemName=MS-TCPS.OpenEnclaveSDK-VSIX)
  Visual Studio extension, v0.7 or later.  The extension can be installed via that marketplace link, or from within
  Visual Studio.  (Do Extensions -> Manage Extensions -> Online -> search for "enclave".)  You must restart Visual Studio after
  installing the extension.

You will also need a build machine running Ubuntu 16.04 (64-bit) or Ubuntu 18.04.  This can be
any of the following:
- a remote Linux machine
- an [Azure Confidential Computing VM](https://azure.microsoft.com/en-us/solutions/confidential-compute/)
- a [Linux VM running on the Windows development machine](HyperVLinuxVMSetup.md)

Ideally, the machine should be SGX capable (see [instructions for determining the SGX support level](https://github.com/microsoft/openenclave/blob/master/docs/GettingStartedDocs/SGXSupportLevel.md) if needed),
but a non-SGX machine can still be used:
 - in simulation mode, or
 - if you would like to install the Open Enclave Host-Verify SDK and build evidence verification applications without enclaves.

On the Linux build machine, or after opening an ssh session into the VM:

- Install the Open Enclave SDK.  See [installation instructions for Ubuntu 16.04](https://github.com/microsoft/openenclave/blob/master/docs/GettingStartedDocs/install_oe_sdk-Ubuntu_16.04.md)
  or [installation instructions for Ubuntu 18.04](https://github.com/microsoft/openenclave/blob/master/docs/GettingStartedDocs/install_oe_sdk-Ubuntu_18.04.md), except that step 2 on those pages is outdated and result
  in SGX not working.  Instead, replace step 2 with the
  [SGX1 instructions](https://github.com/microsoft/openenclave/blob/master/docs/GettingStartedDocs/Contributors/SGX1GettingStarted.md)
  prior to the Install section, which should work with either 16.04 or 18.04 even though
  the page only mentions 16.04.

Finally, configure Visual Studio with the address (or name) of your Linux build machine,
via Tools -> Options -> Cross Platform -> Connection Manager -> Add. This step may take
a minute or two, as Visual Studio will copy some files locally for use by IntelliSense.

## Walkthrough: Creating a C/C++ Enclave Application

We will now walk through the process of creating a C/C++ application that uses an enclave.

1. Create a new Linux application using File -> New -> Project and find the Linux console
   app template, which 
   is called "Console App" (note: NOT the "Console App (.NET Core)") with the Linux
   keyword.  (If it is not immediately visible, the template can be found under
   Installed -> Visual C++ -> Cross Platform -> Linux.)
   Give the project a name, LinuxApp for example.  This will create a "Hello World" console application.
   Alternatively, if you already have such a Linux application using a Visual Studio project
   file (.vcxproj file), you can start from your existing application.
2. Configure the application project to use your Linux build environment, by right clicking
   on the project in the Solution Explorer and selecting Properties -> Configuration
   Properties -> General -> Remote Build Machine, and explicitly set it to the build machine
   you configured in the Connection Manager.  (Due to a current Visual Studio bug, this step
   is required even if the correct value is shown by default. In other words, make sure the
   connection is shown in **bold**.)
3. Also update Configuration Properties -> Debugging -> Remote
   Debug Machine to your build machine, again due to a current Visual Studio 2019 bug.
   At this point, you should be able to
   build and debug the Hello World application. For further discussion, see the
   [Linux debugging walkthrough](https://docs.microsoft.com/en-us/cpp/linux/deploy-run-and-debug-your-linux-project?view=vs-2019).
4. Create an enclave library project by right clicking on the solution in the Solution Explorer
   and selecting Add -> New Project -> Open Enclave TEE Project (Linux).  (If it is not
   immediately visible, look under Installed -> Visual C++ -> Cross Platform -> Linux.)  Give it a name,
   LinuxEnclave for example.  This will create a sample enclave with an `ecall_DoWorkInEnclave()`
   method exposed to applications, that will simply call an `ocall_DoWorkInHost()` method that
   will be implemented in the application.   In this walkthrough, we'll leave this project
   as is for now, but afterwards you can modify it as you like.
5. Configure the enclave project to use your Linux build environment, as you did in step 2.
   At this point, the enclave would build, but cannot be run as the application doesn't
   invoke it yet.
6. Import the enclave into your application project, by right clicking on the application
   project in the Solution Explorer and selecting Open Enclave Configuration -> Import Enclave,
   then navigate to and select the EDL file (_YourEnclaveProjectName_.edl) in your enclave project.
   This step will modify your application project settings and add some additional files to it,
   including a C file named _YourEnclaveProjectName_\_host.c.  This C file contains a
   `sample_enclave_call()` method that will load and call
   `ecall_DoWorkInEnclave()`, and also contains a sample implementation of a `ocall_DoWorkInHost()`
   method that just prints a message when called.  Although the app could be compiled and run
   at this point, `sample_enclave_call()` is still not called from anywhere.
7. Open the application's main.cpp (or if you are starting from another existing application,
   whatever file you want to invoke enclave code from), and add a call to `sample_enclave_call()`.
   For example, update the main.cpp file to look like this, where the extern C declaration is needed
   because main.cpp is a C++ file whereas the _YourEnclaveProjectName_\_host.c file is a C file:
```C
#include <cstdio>

extern "C" {
    void sample_enclave_call(void);
};

int main()
{
    printf("hello from LinuxApp!\n");
    sample_enclave_call();
    return 0;
}
```
8. For the platform, use x64 or ARM, since Open Enclave currently only supports 64-bit enclaves.
9. You can now set breakpoints in Visual Studio, e.g., inside `ecall_DoWorkInEnclave()` and inside
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

- Building Trusted Applications for TrustZone is not yet supported.
