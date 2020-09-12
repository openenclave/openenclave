OpenSSL
===========

This directory includes the necessary files to build the OpenSSL libraries, including libcrypto and libssl,
that work with Open Enclave. The structure of the directory is as follows.

- openssl/
  The clone of official OpenSSL repository that is included as a git submodule.

- intel-sgx-ssl/
  The clone of Intel SGX SSL that includes the necessary changes to support full LVI mitigation.
  OpenSSL assembly files (generated via perl scripts) may contain constant-encoded instructions
  that are incompatible with LVI mitigation tools. More specifically, the assembler looks for
  the mnemonics rather than the encodings of instructions. Therefore, the relevant changes in the
  repository include:
  - A modified x86_64-xlate.pl perl script that is used to generate assemebly files that are compatible
    with LVI mitigation.
  - A set of patched assemebly files cached in the repository. The reason for the additional patching is
    that those files still contain constant encodings that the modified perl script cannot eliminate.

- CMakeLists.txt
  The cmake script for building and installing the libcrypso and libssl as static libraries.

- bn_conf.h, dso_conf.h, and opensslconf.h
  The copies of header files that are generated during the configuration, which the Windows environment
  that OE depends on does not support; i.e., OE relies on the git bash for the POSIX emulation and
  the version of Perl that comes with the git bash does not support the Pod::Usage module required by the OpenSSL
  configuration scripts. See https://groups.google.com/g/git-for-windows/c/AQf2YbaxH6U/m/mwRScOGRCwAJ
  for the reference on the perl issue with git bash on Windows.

- unsupported.h
  The header lists the OpenSSL APIs, which are unsupported by OE for security concerns.

- append-unsupported
  Script to append the `#include<openssl/unsupported.h>` to the OpenSSL headers that include the
  corresponding APIs. The patched headers will be installed as part of OE release packages.
