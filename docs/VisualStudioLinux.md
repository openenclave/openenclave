# Using Visual Studio to Develop Enclave Applications for Linux

This walkthrough assumes that you are using Visual Studio on a Windows development
machine, and want to develop enclaves for Linux.  If you instead want to use Visual
Studio Code on a development machine running either Windows or Linux, see the
[VS Code instructions](https://github.com/microsoft/openenclave/blob/feature.new_platforms/new_platforms/vscode-extension/README.md).

## Prerequisites

To develop Linux applications using a Windows development machine, you will need the following:

- [Visual Studio](https://visualstudio.microsoft.com/downloads/) 2017 or 2019
  (Community edition, or any other edition)
- ["Linux development with C++" Visual Studio workload](https://devblogs.microsoft.com/cppblog/linux-development-with-c-in-visual-studio/),
  installable via Tools -> Get Tools and Features (on VS2017) or Features (on VS2019) ->
  Workloads -> Other Toolsets -> Linux Development with C++
- [Open Enclave Wizard - Preview](https://marketplace.visualstudio.com/items?itemName=MS-TCPS.OpenEnclaveSDK-VSIX)
  Visual Studio extension, v0.5 or later.  The extension can be installed via that marketplace link, or from within
  Visual Studio.  (For VS2017, do Tools -> Extensions and Updates -> search for "enclave".  For VS2019,
  do Extensions -> Manage Extensions -> search for "enclave.)

You will also need a build machine running Ubuntu 16.04 (64-bit) or Ubuntu 18.04.  This can be
a remote Linux machine, but can simply be a "Generation 2" Linux VM on the Windows
development machine configured as follows:

1. Download an ISO for Ubuntu [18.04](http://releases.ubuntu.com/18.04/) or [16.04](http://releases.ubuntu.com/16.04/).
   A "Server install image" is sufficient.
1. Create a VM as follows.  Open "Hyper-V Manager", and do Action -> New -> Virtual Machine....  
   - On the Specify Generation screen, choose Generation 2.
   - On the Configure Networking screen, choose Default Switch to ensure you can connect to it with a debugger.
   - On the Installation Options screen, choose the ISO file you downloaded.
   - All other options can be either left as the defaults or changed as desired.
1. Disable Secure Boot as follows.  In Hyper-V Manager, right click on the VM you created while it is stopped,
  and select Settings... -> Security and uncheck Enable Secure Boot.
1. Uncheck "Enable checkpoints" under the VM's Settings -> Checkpoints, since SGX will not work with checkpoints.
1. Enable SGX for the VM as follows (this cannot be done from Hyper-V Manager):
   - Download [VirtualMachineSgxSettings.psm1](https://raw.githubusercontent.com/microsoft/openenclave/f28cedce63be9673e20fe54563987189f2565637/new_platforms/scripts/VirtualMachineSgxSettings.psm1)
   - Open an elevated PowerShell window (e.g., type "powershell" and click Run as Administrator)
   - Invoke the following commands, using the path to where you downloaded the file, and replacing MyVM with your VM name:
```
   Set-ExecutionPolicy Bypass -Scope Process
   Import-Module Drive:\Path\to\VirtualMachineSgxSettings.psm1
   Set-VMSgx -VmName MyVM -IsSgxEnabled $True -SgxSize 32
```
1. Start the VM and connect to it (right click, Connect...), finish the initial setup, reboot, and login.
   - Enable OpenSSH server installation when given the choice during setup.
   - All other options are sufficient to leave as the defaults or changed as desired.

On the Linux build machine or VM:

- Install the Open Enclave SDK.  See [installation instructions for Ubuntu 16.04](https://github.com/microsoft/openenclave/blob/master/docs/GettingStartedDocs/install_oe_sdk-Ubuntu_16.04.md)
  or [installation instructions for Ubuntu 18.04](https://github.com/microsoft/openenclave/blob/master/docs/GettingStartedDocs/install_oe_sdk-Ubuntu_18.04.md), except that step 2 on those pages is outdated and result
  in SGX not working.  Instead, replace step 2 with the instructions
   [here](https://github.com/microsoft/openenclave/blob/master/docs/GettingStartedDocs/Contributors/SGX1GettingStarted.md).

Finally, configure Visual Studio with the address (or name) of your Linux build machine,
via Tools -> Options -> Cross Platform -> Connection Manager -> Add.

## Walkthrough: Creating a C/C++ Enclave Application

We will now walk through the process of creating a C/C++ application that uses an enclave.

1. Create a new Linux application using File -> New -> Project and find the Linux console
   app template.  In VS2017, this is called "Console Application (Linux)", and in VS2019,
   it is called "Console App" with the Linux keyword.  Give it a name, LinuxApp for example.
   This will create a "Hello World" console application.  
   Alternatively, if you already have such a Linux application using a Visual Studio project
   file (.vcxproj file), you can start from your existing application.
2. Configure the application project to use your Linux build environment, by right clicking
   on the project in the Solution Explorer and selecting Properties -> Configuration
   Properties -> General -> Remote Build Machine, and explicitly set it to the build machine
   you configured in the Connection Manager.  (Due to a current Visual Studio bug, this step
   is required even if the correct value is shown by default.)
3. If using Visual Studio 2019, also update Configuration Properties -> Debugging -> Remote
   Debug Machine to your build machine, again due to a current Visual Studio 2019 bug.
   (This step is not needed on Visual Studio 2017.)  At this point, you should be able to
   build and debug the Hello World application. For further discussion, see the
   [Linux debugging walkthrough](https://docs.microsoft.com/en-us/cpp/linux/deploy-run-and-debug-your-linux-project?view=vs-2019).
4. Create an enclave library project by right clicking on the solution in the Solution Explorer
   and selecting Add -> New Project -> Open Enclave TEE Project (Linux).   Give it a name,
   LinuxEnclave for example.  This will create a sample enclave with an ecall\_DoWorkInEnclave()
   method exposed to applications, that will simply call an ocall\_DoWorkInHost() method that
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
   sample\_enclave\_call() method that will load and call
   ecall\_DoWorkInEnclave(), and also contains a sample implementation of a ocall\_DoWorkInHost()
   method that just prints a message when called.  Although the app could be compiled and run
   at this point, sample\_enclave\_call() is still not called from anywhere.
7. Open the application's main.cpp (or if you are starting from another existing application,
   whatever file you want to invoke enclave code from), and add a call to sample\_enclave\_call().
   For example, update the main.cpp file to look like this, where the extern C declaration is needed
   because main.cpp is a C++ file whereas the _YourEnclaveProjectName_\_host.c file is a C file:
```C
#include <cstdio>

extern "C" {
    void sample_enclave_call(void);
};

int main()
{
    printf("hello from LinuxApp2!\n");
    sample_enclave_call();
    return 0;
}
```
8. You can now set breakpoints in Visual Studio, e.g., inside ecall\_DoWorkInEnclave() and inside
   ocall\_DoWorkInHost() and run and debug the enclave application just like any other application.

The solution will have three configurations: Debug, SGX-Simulation-Debug, and Release.
The SGX-Simulation-Debug will work the same as Debug, except that SGX support will be emulated
rather than using hardware support.  This allows debugging on hardware that does not support SGX.

For the platform, use x64, since Open Enclave currently only supports 64-bit enclaves.

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
