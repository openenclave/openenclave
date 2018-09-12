
# The helloworld sample

- Written in C
- Minimum code needed for an Open Enclave app
- Helps understand the basic components an OE(Open Enclave) application
- Demonstrates how to build, sign, and run an OE image

 Prerequisite: you may want to read [Common Sample Information](/docs/GettingStartedDocs/sampedocs/README.md#common-sample-information) before going further

## Enclave component
  
  This section shows how to develop and build a simple enclave called helloworld.
  
  ### Develop an enclave
  
   An enclave exposes its functionality to the host application in the form of ECALL (enclave calls). All functions that an enclave defines for the host application to call must be defined with the OE_ECALL modifier and must adhere to the following function prototype:

    OE_ECALL void ecall_method(void* args);
    
    The args parameter can be whatever the host and the enclave agree on.
   
   The OE_ECALL macro exports the function and injects it into a special section (.ecall) in the ELF image, which helps the host, when loading the enclave, build a table of all ECALLs exported by the enclave.

The helloworld sample implements a single ECALL function named, Enclave_HelloWorld, which is called by the host. All it does is making a call back to host.
   
   Here’s the full source listing for the helloworld enclave: [helloworld/enc/enc.c](/samples/make/helloworld/enc/enc.c)
   
    #include <openenclave/enclave.h>
    OE_ECALL void enclave_helloworld(void* args_)
    {
        oe_call_host("host_hello", NULL);
    }
  
  As you can see it contains only a few lines of code, it's by design to keep this sample simple. Here is explanation on each line:  
  
- #include <openenclave/enclave.h>

  An enclave library will be loaded into/run inside a host application, which is a user-mode process. To keep the [Trusted computing base](https://en.wikipedia.org/wiki/Trusted_computing_base) small, the decision was made to make only a specific set of APIs available to an enclave library. A complete list of APIs available to an enclave library could be found [here](/docs/GettingStartedDocs/APIsAvaiableToEnclave.md#apis-available-to-an-enclave-library)
  
The enclave.h header file was included in this sample because it uses the oe_call_host call, which was defined in [enclave.h](/include/openenclave/enclave.h), the header file of the Enclave Runtime library.
  
-  OE_ECALL void enclave_helloworld(void* args_)

     An enclave exposes its functionality via OE_CALLs. Internally, OE constructs a function table from OE_CALLs found in an enclave during compiling time in preparing for handling enclave calls from a host during run time. The only ECALL in this sample is Enclave_HelloWorld.
        
- oe_call_host("host_hello, NULL);

     oe_call_host calls the host function whose name is given by the func parameter. See [Host Application section](README.md#host-application) for how to define the called function in host, eg "host_hello".
     
       oe_result_t oe_call_host(const char *func, void *args)
       
     The args parameter can be whatever the host and the enclave agree on.

     helloworld enclave makes a call into the host's Host_Hello function

 ### Build and sign an enclave 
 
   As mentioned in [how-to-build-and-run-samples](/docs/GettingStartedDocs/sampedocs/README.md#how-to-build-and-run-samples), make files were provided for each sample, you can build the helloworld enclave by running "make build" inside the helloworld/enc directory
  
  For example:
  
    youradminusername@yourVMname:~/openenclave/share/openenclave/samples/helloworld/enc$ make build
    g++ -c -Wall -Werror -O2 -m64 -nostdinc -fPIC -I/home/username/openenclave/include 
        -I/home/username/openenclave/include/libc enc.c -o enc.o
    g++ -o helloworldenc.so enc.o -Wl,--no-undefined  -nostdlib  -nodefaultlibs  -nostartfiles  -Wl,-Bstatic  
        -Wl,-Bsymbolic  -Wl,--export-dynamic  -Wl,-pie -L/home/youradminusername/openenclave/lib/openenclave/enclave  
        -loeenclave -lmbedx509  -lmbedcrypto  -loelibc -loecore
        
 Here is a complete list of files after building this sample
 
    youradminusername@yourVMname:~/openenclave/share/openenclave/samples/helloworld/enc$ ls -l
    total 2220
    -rw-r--r-- 1 219     Aug 16 13:57 enc.c
    -rw-rw-r-- 1 1688    Aug 25 19:53 enc.o
    -rw-r--r-- 1 199     Aug 16 13:57 helloworld.conf
    -rw-rw-r-- 1 1125184 Aug 20 12:35 helloworldenc.signed.so
    -rwxrwxr-x 1 1123200 Aug 25 19:53 helloworldenc.so
    -rw-r--r-- 1 1080    Aug 20 12:35 Makefile
    -rw-r--r-- 1 2455    Aug 16 13:57 private.pem

Notice, not only helloworldenc.so was built, there was a signed library, `helloworldenc.signed.so`, in the above list. It is needed because, on Linux, an enclave is required to be packaged as a shared object that has been digitally signed. 

####  Under the hood for the "make build" operation: 

Here is a listing of key components in the helloworld/enc/Makefile. [complete listing](/samples/make/helloworld/enc/Makefile)

```
       LIBRARIES += -L${OE_LIBDIR}/openenclave/enclave 
       LIBRARIES += -loeenclave
       LIBRARIES += -lmbedx509 
       LIBRARIES += -lmbedcrypto 
       LIBRARIES += -loelibc
       LIBRARIES += -loecore       
      all:
              $(MAKE) build
              $(MAKE) keys
              $(MAKE) sign
       ...
       build:
           g++ -c $(CFLAGS) $(INCLUDES) enc.c -o enc.o
           g++ -o helloworldenc.so enc.o $(LDFLAGS) $(LIBRARIES)          
       sign:
           $(OE_BINDIR)/oesign helloworldenc.so helloworld.conf private.pem
          ...
       keys:
           openssl genrsa -out private.pem -3 3072
           openssl rsa -in private.pem -pubout -out public.pem
 ```           
 
###### Build
   The Makefile's "build" target was for compiling enclave source code and linking its library with its dependent libraries (in the following order)
   - oeenclave
   - mbedx509
   - mbedcrypto
   - oelibc
   - oecore

   `helloworldenc.so` was the resulting enclave library (unsigned)

###### Sign

   The OE SDK comes with a signing tool, `oesign` for digitally signing an enclave library. This tool takes 
   the following parameters.

      $ oesign

      Usage: oesign ENCLAVE CONFFILE KEYFILE

      ENCLAVE is the enclave library file
      The CONFFILE argument is the name of a configuration file that defines enclave metadata, 
      KEYFILE argument is a private RSA key used to sign the enclave.

   For example:
     Here is how you sign the helloworld enclave library , as shown in the Makefile's "sign" target

      oesign helloworldenc.so helloworld.conf private.pem
      
         ENCLAVE: "helloworldenc.so" is the unsigned vesion of the enclave library
         
         CONFFILE: The **helloworld.conf** argument is the name of a configuration file that defines
                   enclave metadata, such as stack size, heap size, and the maximum number of
                   threads (TCSs), product id, and others.
                   
         KEYFILE
              The **private.pem** argument is a private RSA key used to sign the enclave,
              here included with the sample. 
              The Makefile's "keys" taget helps generate RSA keys.
        
           `helloworldenc.signed.so` is the signed version of helloworldenc.so

   Note: Listing of [helloworld/enc/helloworld.conf](/samples/make/helloworld/enc/helloworld.conf)
         
# Host Application

  The host process is what drives the enclave app. It is responsible for managing the lifetime of the enclave and invoking enclave ECALLs but should be considered an untrusted component that is never allowed to handle plaintext secrets intended for the enclave.

  The section we will cover how to develop a host to load and run the helloworld enclave we built above. 

 ### Develop a host
 
 There are relatively fewer restrictions on developing a host app compared to authoring an enclave. In general, you are free to link your choice of additional libraries into the host application. A part of a typical host application job is to manage the life cycle of an enclave. OE SDK provides [Enclave Host Runtime](/docs/GettingStartedDocs/APIsAvaiableToEnclave.md#enclave-host-library) for enclave management.
 
 In this helloworld sample the host app handles the following enclave operations:
 
 - Instantiates an enclave : oe_create_enclave()
     Setup enclave environment for the target enclave library, including allocating resource, validating enclave library, 
    , creating enclave instance, and loading the enclave library.
             
    The hellow sample creates an enclave by calling oe_create_enclave with the path to the signed enclave 
    library file. You can optionally specify OE_ENCLAVE_FLAG_DEBUG if you want to debug an enclave 
     
       oe_create_enclave(argv[1], OE_ENCLAVE_TYPE_SGX, OE_ENCLAVE_FLAG_DEBUG, NULL, 0, &enclave);
       
      argv[1]: the signed enclave library file (helloworldenc.signed.so)
       
      On a successful creation, it turns an opaque enclave handle for any future operation on the enclave
 
      Note: - You can create multiple instances of enclaves this way if there is remaining enclave resource available.
      (such as Enclave Page Cache (EPC))

 - Calls into the enclave: oe_call_enclave()

      A host call an enclave method, use oe_call_enclave with the target oe_enclave_t, the name of the target enclave method, and a    
     pointer to the arguments for the invocation. The target function must have been defined with OE_ECALL.
     For complex enclave methods, both the input and output parameters to the function are usually defined as in a single structure    
     understood by both host and enclave in their shared header.

       oe_call_enclave(enclave, "name_of_the_target_enclave_method", args);

      In this example, the host call the enclave's "Enclave_HelloWorld" defined in the Enclave secction with the enclave returned 
     from the oe_create_enclave call above.
        
       oe_call_enclave(enclave, "enclave_helloworld", NULL);
       
      The Open Enclave handles all the context switching between the host mode and the enclave mode.
        
 - Host OE_OCALL functions for handling calls from the enclave:
 
      Define a set of OE_OCALL functions for an enclave to invoke. Each OE_OCALL function is defined with OE_ECALL modifier 
      must adhere to the following prototype 
     
         OE_OCALL void (*)(void* args);
   
     The meaning of the **args** parameter is defined by the implementer of the
     function and may be null. It can be whatever the host and the enclave agree on.
    
     Host_Hello is the only OE_OCALL function in this sample 
     
     OE_OCALL void host_hello(void* args_)
      
 - Terminates the enclave: oe_terminate_enclave()
 
      To terminate an enclave and free its associated resources such as EPC, call 
      oe_terminate_enclave with the enclave handle that was returned during creation of the enclave.
              
       oe_terminate_enclave(enclave);
 
The listing from [helloworld/host/host.c](/samples/make/helloworld/enc/Makefile)

            #include <openenclave/host.h>
            #include <stdio.h>

            OE_OCALL void host_hello(void* args_)
            {
                fprintf(stdout, "Enclave: Hello World!\n");
            }

            int main(int argc, const char* argv[])
            {
                oe_result_t result;
                int ret = 1;
                oe_enclave_t* enclave = NULL;

                if (argc != 2)
                {
                    fprintf(stderr, "Usage: %s enclave_image_path\n", argv[0]);
                    goto exit;
                }

                result = oe_create_enclave(argv[1], OE_ENCLAVE_TYPE_SGX, 
                                           OE_ENCLAVE_FLAG_DEBUG, NULL, 0, &enclave);
                if (result != OE_OK)
                {
                    fprintf(stderr, "oe_create_enclave(): result=%u", result);
                    goto exit;
                }

                result = oe_call_enclave(enclave, "enclave_helloworld", NULL);
                if (result != OE_OK)
                {
                     fprintf(stderr, "failed: result=%u", result);
                     goto exit;
                }
                ret = 0;
            exit:
               if (enclave)
                  oe_terminate_enclave(enclave);

               return ret;
            }
  
 ### Build a host 
 
   The helloworld sample comes with a Makefile with a "build" target. You can run "make build" to build host app.
  
   Listing of [helloworld/host/Makefile](/samples/make/helloworld/host/Makefile)
    

      all: build

      CFLAGS=-Wall -g
      INCLUDES = -I$(OE_INCLUDEDIR)
      LDFLAGS += -rdynamic

      LIBRARIES += -L$(OE_LIBDIR)/openenclave/host
      LIBRARIES += -loehost
      LIBRARIES += -lcrypto
      LIBRARIES += -lpthread
      LIBRARIES += -ldl

      LIBRARIES += -lsgx_enclave_common
      LIBRARIES += -lsgx_ngsa_ql
      LIBRARIES += -lsgx_urts_ng

      build:
              gcc -c $(CFLAGS) $(INCLUDES) host.c
              gcc -o helloworldhost host.o $(LDFLAGS) $(LIBRARIES)

      clean:
              rm -f helloworldhost host.o

# How to Run
     
  Execute "make run" as follows:
   
     ~/samples/helloworld$ make run
     host/helloworldhost ./enc/helloworldenc.signed.so
     Enclave called into host to print: Hello World!
     
  Or you can run the helloworld sample directly on the command line as follows:
   
     ~/samples/helloworld$ host/helloworldhost ./enc/helloworldenc.signed.so
     Enclave called into host to print: Hello World!
         
  To run the helloworld sample simulation mode from the command like, use the following:

     ~/samples/helloworld$ host/helloworldhost ./enc/helloworldenc.signed.so --simulate
     Enclave called into host to print: Hello World!
  
  
