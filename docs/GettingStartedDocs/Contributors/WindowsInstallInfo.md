Basic Install on Windows
========================

You can locally install the SDK from the compiled Open Enclave tree by specifying
the install-prefix to the cmake call before calling "ninja install".
From the build subfolder in your source tree:

```cmd
cmake .. -G  Ninja -DNUGET_PACKAGE_PATH=c:\your\path\to\intel_and_dcap_nuget_packages -DCMAKE_INSTALL_PREFIX:PATH=C:\openenclave" -DUSE_LIBSGX=ON
ninja install
```

This will install the [resulting SDK layout](/docs/GettingStartedDocs/Windows_using_oe_sdk.md#open-enclave-sdk-layout) to C:\openenclave
Please note that Nuget_package_Path over here points to the directory where NuGet packackages are installed on your system.
This is the global-packages folder which usually is  %userprofile%\.nuget\packages. For more information, please look [here](https://docs.microsoft.com/en-us/nuget/consume-packages/managing-the-global-packages-and-cache-folders).

## Create a redistributable SDK package

To create a redistributable NuGet package use the following command from your build subfolder:

```cmd
cmake .. -G  Ninja -DNUGET_PACKAGE_PATH=c:\your\path\to\intel_and_dcap_nuget_packages-DCPACK_GENERATOR=NuGet -DUSE_LIBSGX=ON
ninja package
```

This will result in a NuGet package being created in the build folder.

## Create the host-only report verification package

This is work in progress and is coming soon.
