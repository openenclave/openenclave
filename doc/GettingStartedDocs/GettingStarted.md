Getting Started 
===============

In the initial public preview, this SDK is supporting Linux as the main OS. Windows support will be added in the future release.

#### 1. `Determine the SGX support level on your development/target system`

Open Enclave SDK runs on Linux systems, whether those systems are inside virtual machines or directly on top of the bare metal machines.
Differnt feature set of Open Enclave is exposed on a system based on its SGX support level.
Currently, Open Enclave SDK implementation supports three different SGX support levels. Depending on a support level, you can configure the SDK to operate in a certain mode supported by that level. This is explained in [next section](GettingStarted.md#2-understand-the-open-enclave-operation-modes). 

The SDK setup process for each mode has minor differences. Since these differences are not fully compatible between modes, it is imperitive for a user to know the SGX support level on thier target system, to ensure the correct set up of SDK.  

Please refer the following [documentation](SGXSupportLevel.md) to determine the SGX support level for your target system. 

#### 2. `Understand the Open Enclave operation modes`

  The Open Enclave today supports the following three operation modes -

   - `SGX1` mode: This mode can handle all the generic SGX features

   - `SGX1+FLC` mode: In this mode, the Open Enclave SDK takes advantage of the Flexible Launch Control for 
                      better managing architectural enclaves.

   - `Simulator` mode: Open Enclave comes with a SGX software simulator that simulates a subset of the 
                       SGX feature set. This simulator enables Open Enclave SDK to run on systems without 
                       actual SGX hardware support.

   Different Open Enclave operating modes require different SGX support level.

   | Open Enclave operation mode|  SGX support level needed to run on |
   |:---------------------------|:-----------------------------------:|
   | SGX1+FLC                   | SGX1+FLC                            |
   | SGX1                       | SGX1 or SGX1+FLC                    |
   | Simulator                  | Any level                           |
   
   If your target system does not have any SGX hardware support, you want to go with "Simulator" mode 
       
#### 3. `Build and run`

   Choose an operating mode that is compatible with the SGX support level of your target system.
   The links below contain instructions on how to setup Open Enclave SDK environment for a given mode.

  - [Setup Open Enclave SDK for SGX1+FLC mode](SGX1FLCGettingStarted.md)   
  - [Setup Open Enclave SDK for SGX1 mode](SGX1GettingStarted.md)
  - [Setup Open Enclave SDK for Simulator mode](SimulatorGettingStarted.md)
   
Samples
-------------------------------
 
  Under active constrution
    
SDK API Reference
-------------------------------
- [Open Enclave API Reference](refman/md/index.md)
- Additional libraries available inside an encalve
  - [oelibc library](LibcSupport.md): This is the subset of the libc library supported inside an enclave.
  - [oelibcxx library](LibcxxSupport.md): the C++ library functionality supported inside an
    enclave as provided by oelibcxx.
  - [mbedtls library](MbedtlsSupport.md): the [mbedtls](https://tls.mbed.org/) library functionality supported inside an
    enclave as provided by 3rdparty/mbedtls.


