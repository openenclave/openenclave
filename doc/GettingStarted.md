Getting Started with OpenEnclave
================================

Introduction
------------

This document provides a step-by-step tutorial to begin using the OpenEnclave 
SDK. It explains how to obtain, build, and install the SDK. It also describes 
how to develop and build a few simple enclave applications.

Licenses
--------

Microsoft plans to release the OpenEnclave SDK under the MIT license, included 
here in the source distribution.

<https://github.com/Microsoft/openenclave/blob/master/LICENSE>

OpenEnclave builds on various third-party packages. It modifies and 
redistributes libunwind and in addition downloads other third-party packages 
on-the-fly during the build process. Licensing details for all third-party 
packages shown in the table below.

| Package   | License                                                                           |
|-----------|-----------------------------------------------------------------------------------|
| dlmalloc  | <https://github.com/Microsoft/openenclave/blob/master/3rdparty/dlmalloc/LICENSE>  |
| musl libc | <https://github.com/Microsoft/openenclave/blob/master/3rdparty/musl/COPYRIGHT>    |
| OpenSSL   | <https://github.com/Microsoft/openenclave/blob/master/3rdparty/openssl/LICENSE>   |
| libcxx    | <https://github.com/Microsoft/openenclave/blob/master/3rdparty/libcxx/LICENSE>    |
| libcxxrt  | <https://github.com/Microsoft/openenclave/blob/master/3rdparty/libcxxrt/LICENSE>  |
| libunwind | <https://github.com/Microsoft/openenclave/blob/master/3rdparty/libunwind/LICENSE> |


