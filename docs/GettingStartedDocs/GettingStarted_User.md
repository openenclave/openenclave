Getting Started for Open Enclave (OE) application developers
========================================================

Download and Install OE SDK package
----------------------------------------------
 
 - Download the latest release package from  [OE SDK package releases](https://github.com/Microsoft/openenclave/releases)
 
   Let's say, the downloaded OE SDK package is openenclave-x.x.x-Linux.deb

 - Install it to your target Linux system with the following dpkg command

       sudo dpkg -i openenclave-x.x.x-Linux.deb

   On a successful OE SDK installation, you will have the following components installed under the installation target directory: install_prefix (for example `/opt/openenclave`, the default install dir for the release package)


| Path                                     | Description                     |
|------------------------------------------|---------------------------------|
| <install_prefix>/bin                     | developer tools such as oe-gdb for debugging and oesign for signing your enclaves |
| <install_prefix>/include/openenclave     | OE runtime headers for use in your enclave (enclave.h) and its host (host.h)                        |
| <install_prefix>/include/libc            | c library headers for use inside the enclave. See the API Reference section for supported functions|
| <install_prefix>/include/libcxx          | c++ library headers for use inside the enclave. See the API Reference section for supported functions|
| <install_prefix>/include/mbedtls         | mbedtls library headers for use inside the enclave. See the API Reference section for supported function|
| <install_prefix>/lib/openenclave/enclave | libraries for linking into the enclave, including the libc, libcxx and mbedtls libraries for OE|
| <install_prefix>/lib/openenclave/host    | library for linking into the host process of the enclave|
| <install_prefix>/lib/openenclave/debugger| libraries used by the gdb plug-in for debugging enclaves|
| <install_prefix>/share/doc/openenclave   | OE API documentation in HTML format, which can be browsed starting with index.html. It is consistent with the version of the SDK installed|
| <install_prefix>/share/openenclave/samples  | all OE samples|

  
OE Samples
-------------------------------

  [OE samples](sampedocs/README.md)
    
SDK API Reference
-------------------------------

  [SDK API Reference](APIsAvaiableToEnclave.md)


