Basic Install on Linux
======================

You can locally install the SDK from the compiled Open Enclave tree by specifying
the install-prefix to the cmake call before calling "make install". The SDK does
not currently need to be installed system-wide, so you could choose to install it
into your home directory. From the build subfolder in your source tree:

```bash
cmake -G "Unix Makefiles" -DCMAKE_INSTALL_PREFIX=~/openenclave-install ..
make install
```
or
```bash
cmake -G Ninja  -DCMAKE_INSTALL_PREFIX=~/openenclave-install ..
ninja
```

This would install the [resulting SDK layout](/docs/GettingStartedDocs/Linux_using_oe_sdk.md#open-enclave-sdk-layout)
under `~/openenclave-install` instead of the default `/opt/openenclave`.

Optional Advanced Install
=========================

This section describes the contents of the SDK installation package, how to install the SDK globally
and how to create a redistributable binary package (such as a .deb package)

## Install the SDK tools for all users

If you want the SDK tools to be available to all users and headers/libs
available from a system default location, you may opt to install system-wide.
This naturally requires root privileges.

Currently, there is no support for a `make uninstall` action, so we recommend
explicitly installing to a path outside the standard `/usr/local/` location.
From the build subfolder:

```bash
cmake -DCMAKE_INSTALL_PREFIX=/opt/openenclave ..
sudo make install
```

On Linux, you can also use the **DESTDIR** mechanism to further modify the target
path at install time, rather than during cmake:

```bash
make install DESTDIR=foo
```

If you also specified a `CMAKE_INSTALL_PREFIX`, this would install the SDK to

```bash
/foo/opt/openenclave
```

## Create a redistributable Debian package

To create a redistributable Debian package, use `cpack`. Specify
the final installation prefix to cmake using the `CMAKE_INSTALL_PREFIX` variable
as above. For example, to create a Debian package that will install the SDK to
/opt/openenclave, run the following from your build subfolder:

```bash
cmake -DCMAKE_INSTALL_PREFIX=/opt/openenclave ..
cpack -G DEB
```

## Create a redistributable RPM package

To create a redistributable RPM package, use `cpack`. Specify
the final installation prefix to cmake using the `CMAKE_INSTALL_PREFIX` variable
as above. For example, to create a Debian package that will install the SDK to
/opt/openenclave, run the following from your build subfolder:

```bash
cmake -DCMAKE_INSTALL_PREFIX=/opt/openenclave ..
cpack -G PRM
```

## Create the host-only report verification package

The host-only report verification package allows non-enclave applications to
validate remote reports from enclaves. The process to create this package
is almost the same as the normal OE SDK. The only difference is the `cpack`
command as shown below:

```bash
cpack -G DEB -D CPACK_DEB_COMPONENT_INSTALL=ON  -D CPACK_COMPONENTS_ALL=OEHOSTVERIFY
```
