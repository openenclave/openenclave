# Getting Started with Open Enclave in Simulation Mode on Windows Machines Without SGX Support

## Platform requirement

Intel® X86-64bit architecture

A version of Windows OS :
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
git clone --recursive https://github.com/openenclave/openenclave.git
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

To deploy all the prerequisities for building Open Enclave, you can run the
following from PowerShell:

```powershell
./scripts/install-windows-prereqs.ps1 -InstallPath C:/oe_prereqs -LaunchConfiguration SGX1-NoDriver -DCAPClientType None
```

## Building on Windows using Developer Command Prompt

Launch the [x64 Native Tools Command Prompt for VS(2017 or 2019)](
https://docs.microsoft.com/en-us/dotnet/framework/tools/developer-command-prompt-for-vs),
which is found in the `Visual Studio 2017` (or 2019) folder in the Start Menu.

Run the command `powershell.exe` to open a PowerShell prompt within the native
tools environment.

From here, use CMake and Ninja to build/install Open Enclave.

To build debug enclaves:

```powershell
cd C:/Users/test/openenclave
mkdir build/x64-Debug
cd build/x64-Debug
cmake -G Ninja -DHAS_QUOTE_PROVIDER=OFF -DNUGET_PACKAGE_PATH=C:/oe_prereqs -DCMAKE_INSTALL_PREFIX=C:/openenclave ../..
ninja
```

Now, using the `ninja install` command will install the SDK in
`C:/openenclave`. To choose a different location, change
the value specified for `CMAKE_INSTALL_PREFIX`

## Run unittests

After building, run all unit test cases using `ctest` to confirm the SDK is built and working as expected.
Note that to run the tests in simulation mode, the `OE_SIMULATION` environment variable must be set to `1`.

Run the following command from the build directory:

```powershell
$env:OE_SIMULATION=1
ctest
```

You will see test logs similar to the following:

```powershell
Test project C:/openenclave/build/x64-Debug
        Start   1: tests/mem
  1/235 Test   #1: tests/mem .............................................................................................................................   Passed    0.02 sec
        Start   2: tests/safecrt
  2/235 Test   #2: tests/safecrt .........................................................................................................................   Passed    0.28 sec
        Start   3: tests/safemath
  3/235 Test   #3: tests/safemath ........................................................................................................................   Passed    0.03 sec
....
....
....
232/235 Test #232: tests/mixed_c_cpp .....................................................................................................................   Passed    0.25 sec
        Start 233: tests/pingpong
233/235 Test #233: tests/pingpong ........................................................................................................................   Passed    0.24 sec
        Start 234: tests/pingpong-shared
234/235 Test #234: tests/pingpong-shared .................................................................................................................   Passed    0.25 sec
        Start 235: samples
235/235 Test #235: samples ...............................................................................................................................   Passed   32.15 sec

100% tests passed, 0 tests failed out of 235

Total Test time (real) = 656.36 sec

The following tests did not run:
         51 - tests/attestation_cert_api (Skipped)
         52 - tests/attestation_plugin (Skipped)
         54 - tests/bigmalloc (Skipped)
         59 - tests/debug-unsigned (Skipped)
         60 - tests/debug-signed (Skipped)
         61 - tests/nodebug-signed (Skipped)
         62 - tests/nodebug-unsigned (Skipped)
        197 - tests/qeidentity (Skipped)
        198 - tests/report (Skipped)
        199 - tests/report_attestation_without_enclave (Skipped)
        202 - tests/sealKey (Skipped)
        207 - tests/global_init_exception (Skipped)
        220 - tests/VectorException (Skipped)
```

Some of the tests are skipped (Not Run) by design because the current simulator is not fully featured yet.

A clean pass of the above unit tests is an indication that your Open Enclave setup was successful.

You can start playing with those Open Enclave samples after following the instructions in the "Install" section below to configure samples for building,

For more information refer to the [Advanced Test Info](AdvancedTestInfo.md) document.

## Install

The `ninja install` command will install the SDK in `C:/openenclave`

## Build and run samples

To build and run the samples, see the [Windows samples README file](/samples/README_Windows.md).
Use `ninja simulate` instead of `ninja run` to execute the samples in simulation mode.
