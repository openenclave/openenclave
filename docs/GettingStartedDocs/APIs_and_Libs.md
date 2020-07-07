# API reference and supported libraries

One of the security principles of writing enclave applications is to minimize the
Trusted Computing Base (TCB) of the enclave code. A consequence of this is that
while the host application has full access to the range of libraries and API
available to all normal mode applications, the enclave is restricted to a much
more constrained set as described below:

## [Open Enclave API](https://openenclave.github.io/openenclave/api/index.html)

The Doxygen documentation of the API exposed by Open Enclave SDK to both enclave and host.

## [Libc support](/docs/LibcSupport.md)

The subset of libc functionality provided by oelibc for use inside an enclave.

## [Libcxx support](/docs/LibcxxSupport.md)

The subset of libcxx functionality provided by oelibcxx for use inside an enclave.

## [mbedtls library](/docs/MbedtlsSupport.md)

The subset of [mbedtls](https://tls.mbed.org/) functionality for use inside an enclave.

## [System EDL files](/docs/SystemEdls.md)

The list of system EDL files that allow for user opt-in.
