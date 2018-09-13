# Open Encalve APIs

## APIs available to an Enclave library

 To keep the Trusted computing base small for better security, the decision was made to make only a specific set of APIs available to an enclave library.

#### Enclave Runtime library

  This library was created to help an enclave interact with its host, and retrieve enclave properties from the secure hardware 
  The current list of enclave APIs can be found [in this header file](/include/openenclave/enclave.h)
  
#### [oelibc library](../LibcSupport.md):

   This is the subset of the libc library supported inside an enclave.
   
#### [oelibcxx library](../LibcxxSupport.md):

   This is the subset of the  C++ library supported inside an enclave.
   
#### [mbedtls library](../MbedtlsSupport.md):

   The [mbedtls](https://tls.mbed.org/) library functionality supported inside an enclave as provided by 3rdparty/mbedtls.

## APIs available to a host application

  There are relatively fewer restrictions on building a host app compared to building an enclave. In general, you are free to link your choice of additional libraries into the host application. The Open Enclave SDK comes with "Enclave Host Runtime" for enclave management.
  
#### Enclave Host Runtime

  This library was created to help a host to manage an enclave life cycle and interact with it.
  The current list of host APIs could be found [in this header file](/include/openenclave/host.h)

