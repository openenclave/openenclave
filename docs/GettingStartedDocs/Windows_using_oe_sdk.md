# Using the Open Enclave SDK on Windows

This document provides a brief overview of how to start exploring the Open Enclave SDK
once you have it installed.

**Note**: The SDK currently does not support 32-bit applications.

## Open Enclave SDK Layout

On Windows, if you installed the SDK using the NuGet package, it is by default installed to `%userprofile%\.nuget\packages`.
If you built the SDK from source and installed it, the SDK is installed to the location specified by CMAKE_INSTALL_PREFIX as described [here](Contributors/WindowsInstallInfo.md#basic-install-on-windows)

It contains the following subfolders:

| Path                         | Description                     |
|------------------------------|---------------------------------|
| bin                          | Developer tools such as oedebugrt.dll for debugging and oesign for signing your enclaves. |
| include\openenclave          | Open Enclave runtime headers for use in your enclave (enclave.h) and its host (host.h). |
| include\openenclave\3rdparty | Headers for libc, libcxx and mbedlts libraries for use inside the enclave.<br>See the API Reference section for supported functions. |
| lib\openenclave\cmake        | Open Enclave SDK CMake Package for integration with your CMake projects. See [README.md](\cmake\sdk_cmake_targets_readme.md) for more details. |
| lib\openenclave\enclave      | Libraries for linking into the enclave, including the libc, libcxx and mbedtls libraries for Open Enclave. |
| lib\openenclave\host         | Library for linking into the host process of the enclave. |
| lib\openenclave\debugger     | Libraries used by the gdb plug-in for debugging enclaves. |
| share\openenclave\samples    | Sample code showing how to use the Open Enclave SDK. |

## Configure environment variables for Open Enclave SDK for Windows

- Set `CMAKE_PREFIX_PATH` to the point to the cmake directory of the Open Enclave SDK installation

As an example, if you installed the SDK to C:\openenclave, then you would set `CMAKE_PREFIX_PATH` as shown below.

```cmd
set CMAKE_PREFIX_PATH=C:\openenclave\lib\openenclave\cmake
```

## Samples

One way to determine if your machine is correctly configured to build and run
Open Enclave apps is to execute the samples. A description of all the included samples,
what each one illustrates, and how to build and run them  can be found in
[share/openenclave/samples/README.md](/samples/README.md).

Additional documentation is also available for:
- [Building and signing enclaves](/docs/GettingStartedDocs/buildandsign.md)
- [Debugging enclave applications](/docs/GettingStartedDocs/Debugging.md)

## APIs and supported libraries

Please look [here](/docs/GettingStartedDocs/APIs_and_Libs.md).
