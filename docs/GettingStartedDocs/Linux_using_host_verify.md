# Using the Open Enclave Host-Verify SDK on Linux

This document provides a brief overview of how to start exploring the Open Enclave Host-Verify SDK
once you have it installed.

**Note**: The SDK currently does not support 32-bit applications.

## Open Enclave Host-Verify SDK Layout

On Linux, by default, the Open Enclave Host-Verify SDK is installed to `/opt/openenclave`.

It contains the following subfolders:

| Path                         | Description                     |
|------------------------------|---------------------------------|
| bin                          | Developer tool for verifying attestation evidence or certificates. |
| include/openenclave          | Open Enclave Host-Verify runtime headers for use in your attestation verifier application. |
| lib/openenclave/cmake        | Open Enclave Host-Verify SDK CMake Package for integration with your CMake projects. |
| lib/openenclave/host         | Libraries for linking into the attestation verifier application. |
| share/openenclave/samples    | Sample code showing how to use the Open Enclave Host-Verify SDK. |

On Linux, the Open Enclave Host-Verify SDK installation also contains the following folder:
| share/pkgconfig              | Pkg-config files for header and library includes when building Open Enclave Host-Verify apps. |

## Configure environment variables for Open Enclave Host-Verify SDK for Linux
For ease of development, we recommend adding:
- Open Enclave SDK `install` folder to `CMAKE_PREFIX_PATH`, for use of the [CMake package](/cmake/sdk_cmake_targets_readme.md).
- Open Enclave SDK `pkgconfig` folder to `PKG_CONFIG_PATH`, for use of `pkg-config`.

You can do this by sourcing the `openenclaverc` file that is distributed with the SDK:

```bash
source /opt/openenclave/share/openenclave/openenclaverc
```

## Samples

One way to determine if your machine is correctly configured to build and run
Open Enclave apps is to execute the samples. A description of the host-verify sample,
what it illustrates, and how to build and run it can be found in
[share/openenclave/samples/host_verify/README.md](/samples/host_verify/README.md).
