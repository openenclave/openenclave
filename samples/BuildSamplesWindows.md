# Building and Running the Samples on Windows

All the samples that come with the Open Enclave SDK installation are structured into two subdirectories (one for enclave and one for host) accordingly.

| Files/dir      |  contents                                   |
|:---------------|---------------------------------------------|
| Makefile       | Makefile for building all samples           |
| CMakeLists.txt | CMake file for building for all samples     |
| enclave        | Files needed for building the sample enclave|
| host           | Files needed for building the host          |

## Install prerequisites

Before you can build and run samples, you would need to install the prerequisites as described in the [getting started documentation](https://github.com/openenclave/openenclave/tree/master/docs/GettingStartedDocs).

## Prepare samples

Building a sample will write intermediate and output files into the sample directory. If you would like to use a separate working directory for building samples, you can copy the samples to your working directory first. For example, if the SDK was installed to C:\openenclave:

```cmd
xcopy C:\openenclave\share\openenclave\samples C:\mysample
```

## Steps to build and run samples

1. [x64 Native Tools Command Prompt for VS2017 or 2019](
https://docs.microsoft.com/en-us/dotnet/framework/tools/developer-command-prompt-for-vs)

2. Add the cmake directory in the Open Enclave SDK installation to `CMAKE_PREFIX_PATH`.

As an example, if the Open Enclave SDK is installed to `C:\openenclave`, then you would set `CMAKE_PREFIX_PATH` as shown below

```cmd
set CMAKE_PREFIX_PATH=%CMAKE_PREFIX_PATH%;C:\openenclave\lib\openenclave\cmake
```

3. To build a sample using CMake, change directory to your target sample directory and execute the following commands:

```cmd
mkdir build
cd build
cmake .. -G Ninja -DNUGET_PACKAGE_PATH=C:\oe_prereqs
ninja
```

4. To run the sample, use below:

```cmd
ninja run
```

5. Some of the samples can be run in simulation mode. To run the sample in simulation mode, use below:

```cmd
ninja simulate
```

### Note

More detailed information on what the samples contain, how oeedger8r is used and what files are generated during the build process can be found in the [helloworld sample README](helloworld/README.md).

For details on how to configure build and sign options, refer to [Enclave Building and Signing](https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/buildandsign.md).

## Build and Run samples with LVI mitigation

Refer to the documentation provided in the [LVI section of the helloworld sample](helloworld/README.md#build-and-run-with-lvi-mitigation) for more details.
