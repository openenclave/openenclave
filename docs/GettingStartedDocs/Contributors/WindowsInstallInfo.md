Basic Install on Windows
========================

You can locally install the SDK from the compiled Open Enclave tree by specifying
the install-prefix to the cmake call before calling `ninja install`.
From the build subfolder in your source tree:

For SGX1 + FLC targets, assuming that the Intel and Azure DCAP NuGet packages are installed to `C:\oe_prereqs` and the Open Enclave SDK is installed to `C:\openenclave`:

```cmd
cmake .. -G  Ninja -DNUGET_PACKAGE_PATH=C:\oe_prereqs -DCMAKE_INSTALL_PREFIX:PATH=C:\openenclave
ninja install
```

For SGX1 targets:

```cmd
cmake .. -G  Ninja -DNUGET_PACKAGE_PATH=C:\oe_prereqs -DCMAKE_INSTALL_PREFIX:PATH=C:\openenclave -DHAS_QUOTE_PROVIDER=OFF
ninja install
```

This will install the [resulting SDK layout](/docs/GettingStartedDocs/Windows_using_oe_sdk.md#open-enclave-sdk-layout) to C:\openenclave
Please note that NUGET_PACKAGE_PATH in the above command points to the directory where where the Intel SGX & DCAP Client NuGet packages packackages are installed on your system.

## Create a redistributable SDK package

To create a redistributable NuGet package use the following command from your build subfolder:

```cmd
cmake .. -G  Ninja -DNUGET_PACKAGE_PATH=C:\oe_prereqs -DCPACK_GENERATOR=NuGet
ninja package
```

This will result in a NuGet package being created in the build folder.

## Create the host-only report verification package

The host-only report verification package allows non-enclave applications to
validate remote reports from enclaves.

```cmd
cpack -D CPACK_NUGET_COMPONENT_INSTALL=ON -DCPACK_COMPONENTS_ALL=OEHOSTVERIFY
```
