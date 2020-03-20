# Using the Open Enclave SDK on Linux

This document provides a brief overview of how to start exploring the Open Enclave SDK
once you have it installed.

**Note**: The SDK currently does not support 32-bit applications.

## Open Enclave SDK Layout

On Linux, by default, the Open Enclave SDK is installed to `/opt/openenclave`.

It contains the following subfolders:

| Path                         | Description                     |
|------------------------------|---------------------------------|
| bin                          | Developer tools such as oegdb for debugging and oesign for signing your enclaves. |
| include/openenclave          | Open Enclave runtime headers for use in your enclave (enclave.h) and its host (host.h). |
| include/openenclave/3rdparty | Headers for libc, libcxx and mbedlts libraries for use inside the enclave.<br>See the API Reference section for supported functions. |
| lib/openenclave/cmake        | Open Enclave SDK CMake Package for integration with your CMake projects. See [README.md](/cmake/sdk_cmake_targets_readme.md) for more details. |
| lib/openenclave/enclave      | Libraries for linking into the enclave, including the libc, libcxx and mbedtls libraries for Open Enclave. |
| lib/openenclave/host         | Library for linking into the host process of the enclave. |
| lib/openenclave/debugger     | Libraries used by the gdb plug-in for debugging enclaves. |
| share/openenclave/samples    | Sample code showing how to use the Open Enclave SDK. |

On Linux, the Open Enclave SDK installation also contains the following folder:
| share/pkgconfig              | Pkg-config files for header and library includes when building Open Enclave apps. |

## Configure environment variables for Open Enclave SDK for Linux
For ease of development, we recommend adding:
- Open Enclave SDK `bin` folder to `PATH`, for use of our tools (such as `oegdb` and `oeedger8r`).
- Open Enclave SDK `install` folder to `CMAKE_PREFIX_PATH`, for use of the [CMake package](/cmake/sdk_cmake_targets_readme.md).
- Open Enclave SDK `pkgconfig` folder to `PKG_CONFIG_PATH`, for use of `pkg-config`.

You can do this by sourcing the `openenclaverc` file that is distributed with the SDK:

```bash
source /opt/openenclave/share/openenclave/openenclaverc
```

## Samples

One way to determine if your machine is correctly configured to build and run
Open Enclave apps is to execute the samples. A description of all the included samples,
what each one illustrates, and how to build and run them  can be found in
[share/openenclave/samples/README.md](/samples/README_Linux.md).

Additional documentation is also available for:
- [Building and signing enclaves](/docs/GettingStartedDocs/buildandsign.md)
- [Debugging enclave memory](/docs/GettingStartedDocs/Debugging.md)

## APIs and supported libraries

Please look [here](/docs/GettingStartedDocs/APIs_and_Libs.md).
