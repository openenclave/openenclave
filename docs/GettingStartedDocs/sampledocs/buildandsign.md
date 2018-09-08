# Enclave Building and Siging

## Building the Enclave

   As with the Intel SGX SDK, Open Enclave currently only supports building single-binary enclaves. Additionally, these enclave binaries must be built with the following additional options as shown:
   
    - Include paths:
      - /opt/openenclave/include
      - /opt/openenclave/include/libcxx
      - /opt/openenclave/include/libc
    - Compiler options: 
      - nostdinc (and -nostdinc++ if using c++) 
      -	-m64
      -	-fPIC
    - Link library path: /opt/openenclave/lib/openenclave/enclave
    - Linker options:
      -	-nostdlib
      -	-nodefaultlibs
      -	-nostartfiles 
      -	-Wl,-Bstatic
      -	-Wl,-Bsymbolic 
      -	-Wl,--export-dynamic 
      -	-Wl,--no-undefined
      -	-Wl,-pie
      -	-Wl,-eoe_main
    - Link libraries:
      - -Wl,--start-group -Wl,--whole-archive -loeenclave -loecore -Wl,--end-group
      -	-loelibcxx -loelibc -lmbedtls -lmbedx509 -lmbedcrypto
      
   Regarding the additional include and library paths, each sample uses default path constants from config.mak (eg. /opt/openenclave/share/openenclave/config.mak), which you can use as a reference when working with Open Enclave projects.
   -$(OE_INCLUDEDIR) mapping to /opt/openenclave/include
   -$(OE_LIBDIR) mapping to /opt/openenclave/lib
    
   To touch on a couple of the other options that require further elaboration:
   
   - The -eoe_main linker option is necessary to ensure that the oe_main entry function into the enclave is used as the default entry point. 
   - The libraries specified by -loeenclave and -loecore must be linked as a group with the --whole-archive option to prevent the linker from optimizing away some functions necessary for enclave runtime functionality. 
   - The order of linking is important. As illustrated in each sample's Makefile, the oeenclave and oecore libraries need to be linked before the others in the presented order.

## Signing the Enclave

   Before the enclave can be run, the properties that define how the enclave should be loaded need to be specified for the enclave. These properties, along with the signing key, define the enclave identity that is used for attestation and sealing operations. 
    In the Open Enclave SDK, these properties can be attached to the enclave as part of the signing process. To do so, you will need to use the oesign tool, which takes the following parameters:
    
    Usage: oesign ENCLAVE CONFFILE KEYFILE
    
    For example, to sign the helloworld sample enclave:
    ~/mysamples$ cd helloworld/enc
    ~/mysamples/helloworld/enc$ /opt/openenclave/bin/oesign helloworld_enc enc.conf private.pem
    
    When signing the enclave, the KEYFILE specified must contain a 3072-bit RSA keys with exponent 3. For any sample, this private RSA keypair is provided by private.pem argument. To generate your own private keypair yourself, you can install the OpenSSL package and run:
    $ openssl genrsa -out myprivate.pem -3 3072
    The CONFFILE is a simple text file that defines enclave settings. All the settings must be provided for the enclave to be successfully loaded:
    -	Debug: Is the enclave allowed to load in debug mode? 
    -	NumTCS: The number of thread control structures (TCS) to allocate in the enclave. This determines the maximum number of concurrent threads that can be executing in the enclave.
    -	NumStackPages: The number of stack pages to allocate for each thread in the enclave.
    -	NumHeapPages: The number of pages to allocate for the enclave to use as heap memory. 
    All these properties will also be reflected in the UniqueID (MRENCLAVE) of the resulting enclave. In addition, the following two properties are defined by the developer and map directly to the following SGX identity properties:
    -	ProductID: The product identity (ISVPRODID) for the developer to distinguish between different enclaves signed with the same MRSIGNER value.
    -	SecurityVersion: The security version number for the enclave (ISVSVN), which can be used to prevent rollback attacks against sealing keys. This value should be incremented whenever a security fix is made to the enclave code.
    
    Here is the example from enc.conf used in the helloworld sample:
    # Enclave settings:
    Debug=1
    NumHeapPages=1024
    NumStackPages=1024
    NumTCS=2
    ProductID=1
    SecurityVersion=1
    
    As a convenience, you can also specify the enclave properties in code using the OE_SET_ENCLAVE_SGX macro. For example, the equivalent properties could be defined in any .cpp compiled into the enclave: 
    
    OE_SET_ENCLAVE_SGX(
        1,    /* ProductID */
        1,    /* SecurityVersion */
        true, /* AllowDebug */
        1024, /* HeapPageCount */
        1024, /* StackPageCount */
        2);   /* TCSCount */
    Specifying the enclave properties using the OE_SET_ENCLAVE_SGX also allows you to run an enclave in debug mode without signing it first. In this case, the enclave is treated as having the standard AuthorID (MRSIGNER) identity of:
        MRSIGNER=CA9AD7331448980AA28890CE73E433638377F179AB4456B2FE237193193A8D0A
    Any properties set in the code also serve as default values when the enclave is signed using oesign, so the signing CONFFILE only needs to specify override parameters during signing. For example, to toggle an enclave to disable debug mode when signed, it would only need to specify:
    # Enclave settings:
    Debug=0


# Building the Host App

There are relatively fewer restrictions on building a host app compared to building the enclave. In general, you are free to link your choice of additional libraries into the host application, although the following are necessary for Open Enclave:
- Include path: /opt/openenclave/include 
- Link library path: /opt/openenclave/lib/openenclave/host
- Linker option: -rdynamic
- Link libraries: -loehost -lcrypto -lpthread -ldl -lsgx_enclave_common -lsgxoeql -lsgx_urts_ng

As with building an enclave, the /opt/openenclave/share/openenclave/config.mak provides an example of default path constants to use when working with Open Enclave projects.
