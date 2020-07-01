# Using the Open Enclave Host-Verify SDK on Windows

This document provides a brief overview of how to start exploring the Open Enclave Host-Verify SDK
once you have it installed.

**Note**: The SDK currently does not support 32-bit applications.

## Open Enclave Host-Verify SDK Layout

On Windows, if you installed the SDK using the NuGet package, it is by default installed to `%userprofile%\.nuget\packages`.
If you built the SDK from source and installed it, the SDK is installed to the location specified by `CMAKE_INSTALL_PREFIX` as described [here](Contributors/WindowsInstallInfo.md#basic-install-on-windows)

It contains the following subfolders:

| Path                         | Description                     |
|------------------------------|---------------------------------|
| bin                          | Developer tool for verifying attestation evidence or certificates. |
| include/openenclave          | Open Enclave Host-Verify runtime headers for use in your attestation verifier application. |
| lib/openenclave/cmake        | Open Enclave Host-Verify SDK CMake Package for integration with your CMake projects. |
| lib/openenclave/host         | Libraries for linking into the attestation verifier application. |
| share/openenclave/samples    | Sample code showing how to use the Open Enclave Host-Verify SDK. |

## Configure environment variables for Open Enclave Host-Verify SDK for Windows

- Set `CMAKE_PREFIX_PATH` to the point to the cmake directory of the Open Enclave Host-Verify SDK installation

As an example, if you installed the SDK to C:\openenclave, then you would set `CMAKE_PREFIX_PATH` as shown below.

```cmd
set CMAKE_PREFIX_PATH=C:\openenclave\lib\openenclave\cmake
```

## Samples

One way to determine if your machine is correctly configured to build and run
Open Enclave apps is to execute the samples. A description of the host-verify sample,
what it illustrates, and how to build and run it can be found in
[share/openenclave/samples/host_verify/README.md](/samples/host_verify/README.md).
