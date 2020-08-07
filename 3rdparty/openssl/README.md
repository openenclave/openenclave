OpenSSL
===========

This directory includes the necessary files to build the OpenSSL libraries, including libcrypto and libssl,
that work with Open Enclave. The structure of the directory is as follows.

- openssl/
  The clone of official OpenSSL repository that is included as a git submodule.

- CMakeLists.txt
  The cmake script for building and installing the libcrypso and libssl as static libraries.

- bn_conf.h, dso_conf.h, and opensslconf.h
  The copies of header files that are generated during the configuration, which the Windows environment
  that OE depends on does not support; i.e., OE relies on the git bash for the POSIX emulation and
  the version of Perl that comes with the git bash does not support the Pod::Usage module required by the OpenSSL
  configuration scripts. See https://groups.google.com/g/git-for-windows/c/AQf2YbaxH6U/m/mwRScOGRCwAJ
  for the reference on the perl issue with git bash on Windows.
