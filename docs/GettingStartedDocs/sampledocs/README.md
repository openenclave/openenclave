# OE Samples (work in progress)

All the samples that come with the Open Enclave SDK installation share similar directory structure and build instructions. The section contains general information on how to setup/build/sign/run all samples. It's important that you read information on this page before jumping into any individual sample.

## Common Sample information

### Prepare samples

Building samples involves writing files into the working directory, which is not allowed in /opt unless it's running in the context of superuser(sudo).

To avoid this sudo requirement, you may want to first copy them to a user directory of your choice then build and run on those local
copy. 

 For example:

     $ cp -r /opt/openenclave/share/openenclave/samples ~/mysamples

### How Sample source code directories were structured

   Open Enclave SDK helps developers build enclave applications. An enclave application is partitioned into an untrusted component (called a host) and a trusted component (called an enclave). An enclave is a secure container whose memory (text and data) is protected from access by outside entities, including the host, privileged users, and even the hardware. All functionality that needs to be run in a Trusted Execution Environment (TEE) should be compiled into the enclave binary. The enclave may run in an untrusted environment with the expectation that secrets will not be compromised. A host is a normal user mode application that loads an enclave into its address space before starting interacting with an enclave. 
   
 ![Sample components diagram](sampledirstructure.png)

 All the samples that come with the Open Enclave SDK installation are all structured into two subdirectories (one for enclave and oen for host) accordingly 
   
   | Files/dir    |  contents                                   |
   |:-------------|---------------------------------------------|
   | Makefile     | Makefile for the whole samples              |
   | ./enc        | files needed for building the sample enclave|
   | ./host       | files needed for building the host          |

   For example:
     
           /home/yourusername:~/openenclave/share/openenclave/samples/helloworld$ ls -l
            total 12
            drwxr-xr-x 2 yourusername yourusername 4096 Aug 16 13:59 enc
            drwxr-xr-x 2 yourusername yourusername 4096 Aug 16 13:59 host
            -rw-r--r-- 1 yourusername yourusername  245 Aug 16 13:57 Makefile
 
### How to build and run samples

  Each sample comes with a set of simple Makefiles to simplify the sample building process, which involves building and signing 
binaries.
    
  To build a sample, change directory to your target sample directory and run "make build" to build the sample
  and run "make run" to run it.
     
   For example:

         yourusername@yourVMname:~/openenclave/share/openenclave/samples$ cd helloworld/
         yourusername@yourVMname:~/openenclave/share/openenclave/samples/helloworld$ ls
         enc  host  Makefile

         yourusername@yourVMname:~/openenclave/share/openenclave/samples/helloworld$ make build
         ...
         yourusername@yourVMname:~/openenclave/share/openenclave/samples/helloworld$ make run
         host/helloworldhost ./enc/helloworldenc.signed.so
         Enclave called into host to print: Hello World!

  Note: For more advanced users that want to know all the detailed building and signing configuration see [here](buildandsign.md)
  
   
## Samples

  It's recommended to go through the following samples in the order listed below.

#### [HelloWorld](/samples/make/helloworld/README.md)

#### [Remote Attestation](/samples/make/remote_attestation/README.md)

#### Echo (Under construction)
 
  - Written in C++
  - Demonstrates the parameter passing feature
  - Showcase the enclave public APIs
  - In progress
  
#### File-encryptor (Under construction)
 
  - Written in C++
  - Demonstrates data passing and the built-in mbedtls API
  - In progress

####  Data Sealing (Under construction)
  - Written in C++
  - Demonstrates Open Enclave's sealing feature
  - In progress
