# Open Encalve Samples (work in progress)

The section contains information on how to configure/build/run the existing Open Enclave sample

## Configure samples

Before going further, you want to make sure you have a successful Open Enclave setup and can run unittests successfully [install Open Enclave SDK](InstallInfo.md)

   Assuming you installed SDK with the following steps, 

      /home/yourusername/openenclave/build$ cmake -DCMAKE_INSTALL_PREFIX:PATH=~/openenclave-install ..
      /home/yourusername/openenclave/build$ make install

   You will find samples under share/openenclave/samples directory.

        eg.
         /home/yourusername/openenclave/share/openenclave/samples$
         yourusername@yourVMname:~/openenclave/share/openenclave/samples$ ls -l
         -rw-r--r-- 1 yourusername yourusername  234 Aug 14 12:58 config.mak
         drwxr-xr-x 4 yourusername yourusername 4096 Aug 15 16:06 helloworld
         drwxr-xr-x 4 yourusername yourusername 4096 Aug 15 16:06 attestation
         -rw-r--r-- 1 yourusername yourusername  440 Aug  6 17:56 Makefile
         ....

 Note: As part of the sample configuration process, samples/config.mak was created to help setup environment for use
 in building samples.
 
 
 ## How to build and run samples
 
   All the samples share the same directory structure like below:
   
   | Files/dir    |  contents                                |
   |:-------------|:----------------------------------------:|
   | Makefile     | make file for the whole samples          |
   | ./enc        | files needed for build the sample enclave|
   | ./host       | files needed for building the hsot       |

      eg.   
           /home/yourusername:~/openenclave/share/openenclave/samples/helloworld$ ls -l
            total 12
            drwxr-xr-x 2 yourusername yourusername 4096 Aug 16 13:59 enc
            drwxr-xr-x 2 yourusername yournusername 4096 Aug 16 13:59 host
            -rw-r--r-- 1 yourusername yourusername  245 Aug 16 13:57 Makefile

  To build a sample, you want to jump to the target sample directory and run "make build" to build the sample
  and run "make run" to run it.
     
    eg.
         yourusername@yourVMname:~/openenclave/share/openenclave/samples$ cd helloworld/
         yourusername@yourVMname:~/openenclave/share/openenclave/samples/helloworld$ ls
         enc  host  Makefile

         yourusername@yourVMname:~/openenclave/share/openenclave/samples/helloworld$ make build
         ...
         yourusername@yourVMname:~/openenclave/share/openenclave/samples/helloworld$ make run
         host/helloworldhost ./enc/helloworldenc.signed.so
         Enclave: Hello World!

## Samples

#### HelloWorld

  - Written in C
  - Minimun code needed for an Open Enclave app
  - Help understand the basic components an Open Enclave application
  - How to build and run it
  - Introduction to the build environment and basic program structure and image signing
  - More contents to come
  - To run in simulation mode,use
        $ host/helloworldhost ./enc/helloworldenc.signed.so --simulate
  
#### Echo (Under construction)
 
  - Written in C++
  - Demonstrate the parameter passing feature
  - Showcase the enclave public APIs
  - In progress
  
#### File-encryptor (Almost ready)
 
  - Written in C++
  - Demonstrate data passing and the built-in bmedtls api
  - In progress

####  Data Sealing (Under construction)
  - In C++
  - Demonstrate Open Enclave's sealing feature
  - In progress
  
####  Attestation
  - In progress
  
  
