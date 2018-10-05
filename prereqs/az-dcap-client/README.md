az-dcap-client
==============

This directory contains an optional Makefile to install the Azure DCAP client
package. The DCAP client is necessary for performing remote attestation in
Open Enclave apps running in the Azure environment.

You can download and install the package with:

```bash
sudo make
sudo make install
```

If you have a local copy of the package, you can also install from it directly:

```bash
sudo make USE_PKGS_IN=~/my_packages
sudo make install
```

To uninstall the package, you can run:

```bash
sudo make uninstall
sudo make distclean
```
