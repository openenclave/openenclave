# Getting Started with Open Enclave on Windows for systems with support for SGX1 with Flexible Launch Control(FLC)

## Platform requirements

Intel® X86-64bit architecture with SGX1 and Flexible Launch Control (FLC) support. (e.g. Intel Coffee Lake CPU)

Note: To check if your system has support for SGX1 with FLC, please look [here](../SGXSupportLevel.md).

A version of Windows OS with native support for SGX features:
- For server: Windows Server 2016 or 2019
- For client: Windows 10 64-bit version 1709 or newer
- To check your Windows version, run `winver` from the command line

*Note:* The following instructions assume running `powershell` as adminstrator.

## Install Git and Clone the Open Enclave SDK repo

- Download and install Git for Windows from [here](https://git-scm.com/download/win).
- Clone the Open Enclave SDK to a folder of your choice. In these instructions
  we're assuming `C:/Users/test`.

```powershell
cd C:/Users/test/
git clone https://github.com/openenclave/openenclave.git
```

This creates a source tree under the directory called `openenclave`.

## Install project prerequisites

First, change directory into the Open Enclave repository (from wherever you
cloned it):

```powershell
cd C:/Users/test/openenclave
```

Also, make sure the execution policy is set to `RemoteSigned` with the following command.

```powershell
Get-ExecutionPolicy
```

If not, set the policy with the following command and confirm the change by typing `Y`.

```powershell
Set-ExecutionPolicy RemoteSigned
```

Run the following command to deploy all the prerequisites for building Open Enclave:

```powershell
./scripts/install-windows-prereqs.ps1
```

On Windows Server 2019 and versions of Windows 10 newer than 1709, the Intel PSW
should already be automatically installed. Attempting to run the PSW installer will fail if
that is the case. To skip the PSW installer:

```powershell
./scripts/install-windows-prereqs.ps1 -LaunchConfiguration SGX1FLC-NoDriver
```

To install the prerequisites along with the Azure DCAP Client, use the below
command. The Azure DCAP Client is necessary to perform attestation on an Azure
Confidential Computing VM. This command assumes that you would like the
prerequisites to be installed to `C:/oe_prereqs`.

```powershell
./scripts/install-windows-prereqs.ps1 -InstallPath C:/oe_prereqs -LaunchConfiguration SGX1FLC -DCAPClientType Azure
```

If you would like to skip the installation of the Azure DCAP Client, use the
command below:

```powershell
./scripts/install-windows-prereqs.ps1 -InstallPath C:/oe_prereqs -LaunchConfiguration SGX1FLC -DCAPClientType None
```

If you want to install the Azure DCAP Client, you would run the following
command:

```powershell
./scripts/install-windows-prereqs.ps1 -InstallPath C:/oe_prereqs -LaunchConfiguration SGX1FLC -DCAPClientType Azure
```

Once the installation is done, please ignore the following message(s) and continue on to the next step.

```powershell
Please reboot your computer for the configuration to complete.
```

If you prefer to manually install prerequisites, please refer to this
[document](WindowsManualInstallPrereqs.md).

## Building/installation on Windows using Developer Command Prompt

Launch the [x64 Native Tools Command Prompt for VS(2017 or 2019)](
https://docs.microsoft.com/en-us/dotnet/framework/tools/developer-command-prompt-for-vs),
which is found in the `Visual Studio 2017` folder in the Start Menu.

Run the command `powershell.exe` to open a PowerShell prompt within the native
tools environment.

From here, use CMake and Ninja to build/install Open Enclave.

To build debug enclaves:

```powershell
cd C:/Users/test/openenclave
mkdir build/x64-Debug
cd build/x64-Debug
cmake -G Ninja -DNUGET_PACKAGE_PATH=C:/oe_prereqs -DCMAKE_INSTALL_PREFIX=C:/openenclave ../..
ninja
```

Similarly, to build release enclaves, specify the flag
`-DCMAKE_BUILD_TYPE=Release`:

```powershell
cd C:/Users/test/openenclave
mkdir build/x64-Release
cd build/x64-Release
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DNUGET_PACKAGE_PATH=C:/oe_prereqs -DCMAKE_INSTALL_PREFIX=C:/openenclave ../..
ninja
```

To build enclaves with LVI mitigation, specify the flag `-DLVI_MITIGATION=ControlFlow`:
```powershell
cd C:/Users/test/openenclave
mkdir build/x64-LVI
cd build/x64-LVI
cmake -G Ninja -DLVI_MITIGATION=ControlFlow -DNUGET_PACKAGE_PATH=C:/oe_prereqs -DCMAKE_INSTALL_PREFIX=C:/openenclave ../..
ninja
```
Refer to the [LVI Mitigation](AdvancedBuildInfo.md#lvi-mitigation) documentation for further information.

Now, using the `ninja install` command will install the SDK in
`C:/openenclave`. To choose a different location, change
the value specified for `CMAKE_INSTALL_PREFIX`.

## Run unit tests

After building, run all unit test cases using `ctest` to confirm the SDK is built and working as expected.

Run the following command from the build directory to run tests, (in this example, we are testing the debug build):

```powershell
ctest
```

You will see test logs similar to the following:

```powershell
  Test project C:/Users/test/openenclave/build/x64-Debug
        Start   1: tests/lockless_queue
  1/107 Test   #1: tests/lockless_queue ..................................   Passed    3.49 sec
        Start   2: tests/mem
  2/107 Test   #2: tests/mem .............................................   Passed    0.01 sec
  ...
  ....
100% tests passed, 0 tests failed out of 107
```

A clean pass of the above unit tests run is an indication that your Open Enclave setup was successful. 

For more information refer to the [Advanced Test Info](AdvancedTestInfo.md) document.

## Build and run samples

To build and run the samples without building and then installing the OE SDK, please refer to the [README for Windows samples](/samples/README_Windows.md).

## Known Issues

Not all tests currently run on Windows. See [tests/CMakeLists.txt](/tests/CMakeLists.txt) for a list of supported tests.
