# Getting Started with Open Enclave on Windows for systems with support for SGX1

## Platform requirements

Intel® X86-64bit architecture with SGX1.

Note: To check if your system has support for SGX1, please look [here](../SGXSupportLevel.md).

A version of Windows OS with native support for SGX features:
- For server: Windows Server 2016
- For client: Windows 10 64-bit version 1709 or newer

## Install Git and Clone the Open Enclave SDK repo

- Download and install Git for Windows from [here](https://git-scm.com/download/win).
- Clone the Open Enclave SDK to folder of your choice. In these instructions
  we're assuming `openenclave`.

```powershell
git clone https://github.com/openenclave/openenclave.git
```

This creates a source tree under the directory called `openenclave`.

## Install project prerequisites

First, change directory into the Open Enclave repository (from wherever you
cloned it):

```powershell
cd openenclave
```

To deploy all the prerequisities for building Open Enclave, you can run the
following from PowerShell. Note that the Data Center Attestation Primitives
(DCAP) Client is not used for attestation on systems which have support for SGX1
without support for Flexible Launch Control (FLC). The below example assumes you
would like to install the packages to `C:/oe_prereqs`.

```powershell
./scripts/install-windows-prereqs.ps1 -InstallPath C:/oe_prereqs -LaunchConfiguration SGX1 -DCAPClientType None
```

On Windows 10, the Intel PSW is delivered via Windows Update. Running the
executable installer will fail on Windows 10 machines. To skip PSW installation:

```powershell
./scripts/install-windows-prereqs.ps1 -InstallPath C:/oe_prereqs -LaunchConfiguration SGX1-NoDriver -DCAPClientType None
```

If you prefer to manually install prerequisites, please refer to this
[document](WindowsManualInstallPrereqs.md).

## Building on Windows using Developer Command Prompt

Launch the [x64 Native Tools Command Prompt for VS(2017 or 2019)](
https://docs.microsoft.com/en-us/dotnet/framework/tools/developer-command-prompt-for-vs),
which is found in the `Visual Studio 2017` folder in the Start Menu.

Run the command `powershell.exe` to open a PowerShell prompt within the native
tools environment.

From here, use CMake and Ninja to build Open Enclave.

To build debug enclaves:

```powershell
cd openenclave
mkdir build/x64-Debug
cd build/x64-Debug
cmake -G Ninja -DHAS_QUOTE_PROVIDER=OFF -DNUGET_PACKAGE_PATH=C:/oe_prereqs -DCMAKE_INSTALL_PREFIX=install ../..
ninja
```

Later, using the `ninja install` command will install the SDK in
`C:/openenclave/build/x64-Debug/install`. To choose a different location, change
the value specified for `CMAKE_INSTALL_PATH`, but note that the samples tests
will break if an absolute path is specified.

Similarly, to build release enclaves, specify the flag
`-DCMAKE_BUILD_TYPE=Release`:

```powershell
cd openenclave
mkdir build/x64-Release
cd build/x64-Release
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DHAS_QUOTE_PROVIDER=OFF -DNUGET_PACKAGE_PATH=C:/oe_prereqs -DCMAKE_INSTALL_PREFIX=install ../..
ninja
```

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

A clean pass of the above unit tests is an indication that your Open Enclave setup was successful.

You can start playing with the Open Enclave samples after following the instructions in the "Install" section below to configure samples for building,

For more information refer to the [Advanced Test Info](AdvancedTestInfo.md) document.

## Installing the SDK on the local machine

To install the debug SDK on the local machine use the following:

```powershell
cd openenclave/build/x64-Debug
cmake -DCMAKE_INSTALL_PREFIX=C:/openenclave ../..
ninja install
```

This installs the SDK in `C:/openenclave`, the path specified for
`CMAKE_INSTALL_PREFIX`. This install path is assumed for the rest of the
instructions.

## Build and run samples

To build and run the samples, please look [here](/samples/README_Windows.md).

## Known Issues

Not all tests currently run on Windows. See `tests/CMakeLists.txt` for a list of supported tests.
