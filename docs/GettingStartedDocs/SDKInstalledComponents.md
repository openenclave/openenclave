
## Open Enclave SDK Components

On a successful Open Enclave SDK installation, the following components can be found installed under the installation target directory
: install_prefix (for example /opt/openenclave)

It contains the following subfolders:

The following table shows where key components are installed.

| Path                                     | Description                     |
|------------------------------------------|---------------------------------|
| <install_prefix>/bin                     | developer tools such as oe-gdb for debugging and oesign for signing your enclaves |
| <install_prefix>/include/openenclave     | Open Enclave runtime headers for use in your enclave (enclave.h) and its host (host.h)                        |
| <install_prefix>/include/libc            | c library headers for use inside the enclave. See the API Reference section for supported functions|
| <install_prefix>/include/libcxx          | c++ library headers for use inside the enclave. See the API Reference section for supported functions|
| <install_prefix>/include/mbedtls         | mbedtls library headers for use inside the enclave. See the API Reference section for supported function|
| <install_prefix>/lib/openenclave/enclave | libraries for linking into the enclave, including the libc, libcxx and mbedtls libraries for Open Enclave|
| <install_prefix>/lib/openenclave/host    | library for linking into the host process of the enclave|
| <install_prefix>/lib/openenclave/debugger| libraries used by the gdb plug-in for debugging enclaves|
| <install_prefix>/share/doc/openenclave   | Open Enclave API documentation in HTML format, which can be browsed starting with index.html. It is consistent with the version of the SDK installed, which may be more up to date than the Open Enclave API reference in the Yammer group                   |
| <install_prefix>/share/openenclave       | contains Open Enclave samples|

# API Reference
## [oelibc library](../LibcSupport.md): 
   This is the subset of the libc library supported inside an enclave as provided by oelibc.
## [oelibcxx library](../LibcxxSupport.md): 
   The C++ library functionality supported inside an enclave as provided by oelibcxx.
## [mbedtls library](../MbedtlsSupport.md): 
   The [mbedtls](https://tls.mbed.org/) library functionality supported inside an enclave as provided by 3rdparty/mbedtls.
