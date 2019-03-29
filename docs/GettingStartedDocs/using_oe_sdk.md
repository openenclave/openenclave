# Using the Open Enclave SDK

This document provides a brief overview of how to start exploring the Open Enclave SDK
once you have it installed.

## Open Enclave SDK Layout

By default, the Open Enclave SDK is installed to `/opt/openenclave`. It contains the following subfolders:

| Path                         | Description                     |
|------------------------------|---------------------------------|
| bin                          | Developer tools such as oe-gdb for debugging and oesign for signing your enclaves. |
| include/openenclave          | Open Enclave runtime headers for use in your enclave (enclave.h) and its host (host.h). |
| include/openenclave/3rdparty | Headers for libc, libcxx and mbedlts libraries for use inside the enclave.<br>See the API Reference section for supported functions. |
| lib/openenclave/cmake        | Open Enclave SDK CMake Package for integration with your CMake projects. See [README.md](/cmake/sdk_cmake_targets_readme.md) for more details. |
| lib/openenclave/enclave      | Libraries for linking into the enclave, including the libc, libcxx and mbedtls libraries for Open Enclave. |
| lib/openenclave/host         | Library for linking into the host process of the enclave. |
| lib/openenclave/debugger     | Libraries used by the gdb plug-in for debugging enclaves. |
| share/openenclave/samples    | Sample code showing how to use the Open Enclave SDK. |
| share/pkgconfig              | Pkg-config files for header and library includes when building Open Enclave apps. |

## Configure environment variables for Open Enclave SDK

For ease of development, we recommend adding:
- Open Enclave SDK `pkgconfig` folder to `PKG_CONFIG_PATH`
- Open Enclave SDK `bin` folder to `PATH`

You can do this by sourcing the openenclaverc file that is distributed with the SDK:

```bash
source /opt/openenclave/share/openenclave/openenclaverc
```

## Samples

A simple way to determine if your machine is correctly configured to build and run
Open Enclave apps is to execute the samples:

```bash
cp -r /opt/openenclave/share/openenclave/samples ~
cd ~/samples
make world
```

A description of all the included samples and what each one illustrates can be
found in [share/openenclave/samples/README.md](/samples/README.md).

Additional documentation is also available for:
- [Building and signing enclaves](/docs/GettingStartedDocs/buildandsign.md)
- [Debugging enclave memory](/docs/GettingStartedDocs/Debugging.md)

## API references

One of the security principles of writing enclave applications is to minimize the
Trusted Computing Base (TCB) of the enclave code. A consequence of this is that
while the host application has full access to the range of libraries and API
available to all normal mode applications, the enclave is restricted to a much
more constrained set as described below:

#### [Open Enclave API](https://microsoft.github.io/openenclave/api/index.html)

The Doxygen documentation of the API exposed by Open Enclave SDK to both enclave and host.

#### [Libc support](/docs/LibcSupport.md)

The subset of libc functionality provided by oelibc for use inside an enclave.

#### [Libcxx support](/docs/LibcxxSupport.md)

The subset of libcxx functionality provided by oelibcxx for use inside an enclave.

#### [mbedtls library](/docs/MbedtlsSupport.md)

The subset of [mbedtls](https://tls.mbed.org/) functionality for use inside an enclave.
