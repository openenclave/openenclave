Basic Install
=============

You can locally install the SDK from the compiled Open Enclave tree by specifying the install-prefix to the cmake call before calling "make install". As of now, there is no real need to install the SDK system-wide, so you might use a tree in your home directory:
```
build$ cmake -DCMAKE_INSTALL_PREFIX:PATH=~/openenclave ..
build$ make install
```

The following table shows where key components are installed.

| Path                                     | Description                     |
|------------------------------------------|---------------------------------|
| <install_prefix>/bin                     | Programs/Tools                  |
| <install_prefix>/include/openenclave     | Includes                        |
| <install_prefix>/lib/openenclave/enclave | Enclave libraries               |
| <install_prefix>/lib/openenclave/host    | Host libraries                  |
| <install_prefix>/lib/openenclave/debugger| Debugger libraries              |
| <install_prefix>/share/doc/openenclave   | Documentation                   |
| <install_prefix>/share/openenclave       | `Samples` and make/cmake-includes |

For *Makefile* based projects, you may use the make-include in
**<install_prefix>/share/openenclave/config.mak** in your own project for
sourcing variables containing version info and SDK install paths.

For *CMake* based projects, you may use the cmake-include in
**<install_prefix>/share/openenclave/openenclave.cmake** in your own project.
It provides the following targets (e.g., for inclusion in
**target_link_libraries**) to set the required compiler flags, include dirs,
and libraries.

| Target           | Description                                                                         |
|------------------|-------------------------------------------------------------------------------------|
| oecore           | Enclave code: Open Enclave core features. Must be present in all enclave code. |
| oeenclave        | Enclave code: Open Enclave features. These features may depend on the mbedcrypto and oelibc libraries. |
| oelibc           | Enclave code: Open Enclave C library. Includes oecore.                            |
| oelibcxx         | Enclave code: Open Enclave C++ library. Includes oelibc.                             |
| oeidl            | Enclave code: Misc helpers required with IDL-compiled code. Includes oelibc.        |
| oehost           | Host code: Open Enclave intrinsic functions.                                         |
| oehostapp        | Host code: Must be present with host binary for proper linker flags.                |
| oesign           | Build: shorthand for the signing tool executable.                                   |
| oegen            | Build: shorthand for the IDL compiler executable.                                   |


Optional Advanced Install
=========================

This section describes the contents of the SDK installation package, how to install the SDK globally 
and how to create a redistributable binary package (such as a .deb package)

## Make the SDK tools to be available to all users
If you want the SDK tools to be available to all users and headers/libs
available from a system default location, you may opt to install system-wide.
This naturally requires root privileges. Note that there is no uninstall
script (we target an rpm/deb-based SDK install in the future), hence we
recommend overwriting the default (/usr/local/) with a singular tree.

```
build$ cmake -DCMAKE_INSTALL_PREFIX:PATH=/opt/openenclave ..
build$ sudo make install
```

On Linux, there is also the **DESTDIR** mechanism, prepending the install prefix
with the given path:
```
build$ make install DESTDIR=foo
```



## Create Redistributable SDK pacakge
----------------------------------

To create a redistributable package (deb, rpm, ...), use **cpack**. Specify
the final installation prefix to cmake using the CMAKE_INSTALL_PREFIX variable
as above. E.g., to create a Debian package that will install the SDK to
/opt/openenclave, use:

```
build$ cmake -DCMAKE_INSTALL_PREFIX:PATH=/opt/openenclave ..
build$ cpack -G DEB
```
