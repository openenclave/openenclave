Developing your own enclave using Visual Studio
=============

## Using Open Enclave from Windows

This section covers how to use this SDK to develop your own enclave that can run
on both SGX and OP-TEE, and use it from your own application.

**Prerequisites:**
1. Install the Open Enclave Visual Studio Extension
2. To develop for SGX, install the [Prerequisites for SGX](win_sgx_dev.md)
2. To develop for OP-TEE, install the [Prerequisites for OP-TEE](ta_debugging_wsl.md)

**To create your own enclave:**
1. In Visual Studio, add a new Visual C++ "Open Enclave TEE Project".  If you want
to build for OP-TEE (whether in addition to, or instead of, SGX) you will need
to select the path to the ta_dev_kit.mk file in the output of an OP-TEE build.
For example, this might be in a optee_os\out\arm-plat-vexpress\export-ta_arm64\mk
directory.
2. Edit the _YourProjectName_.edl file. Define any trusted APIs (called "ECALLs")
you want to call from your application in the trusted{} section,
and in the untrusted{} section, define any application APIs (called "OCALLs")
that you want to call from your enclave. Definitions must be described using the
[EDL file syntax](https://software.intel.com/en-us/sgx-sdk-dev-reference-enclave-definition-language-file-syntax).
3. Edit the ecalls.c file, and fill in implementations of the ECALL(s) you added.

**To call your enclave from an application project:**
1. In Visual Studio, create a new Visual C++ project, or open an existing
one, that will build a normal application that will call your enclave APIs.
2. Right click on your application project, select
"Open Enclave Configuration"->"Import Enclave", and select the
_YourProjectName_.edl file from your enclave project.
3. Add code in your app to call oe\_create\__YourEDLFileName_\_enclave(),
any ECALLs you added, and
oe\_terminate\_enclave().  You will need to #include <openenclave/host.h> 
and <_YourEDLFileName_\_u.h> for your ECALLs.
See the sample apps for an example.

OP-TEE only allows one thread per TA to be in an ECALL (i.e., a call into
a TA from a host app).  Even if it has an OCALL (i.e., an out-call
back into the host app) in progress, the ECALL must complete before
another ECALL can enter the TA.  SGX, on the other hand, would allow a
second ECALL to enter.  So if you want them to function identically, host apps
can pass the OE\_ENCLAVE\_FLAG\_SERIALIZE\_ECALLS
flag when creating an enclave to automatically get the OP-TEE like behavior
for both SGX and TrustZone.


**Then to build the enclave for OP-TEE:**

1. Using [Bash on Ubuntu on Windows](https://docs.microsoft.com/en-us/windows/wsl/about) shell, 
cd to your enclave project's "optee" subdirectory.  If you added additional
source files to your enclave project in Visual Studio, also add them to the 
sub.mk in that directory.
2. By default, the project is configured to build for the vexpress-qemu\_armv8a flavor of OP-TEE.
If you want to build for vexpress-qemu\_virt or ls-ls1012grapeboard, edit the sub.mk
file in the project's "optee" subdirectory, and change the 'libdirs' line accordingly.
For vexpress-qemu\_virt, you will also need to change the CROSS_COMPILE line in linux\_gcc.mak
to "CROSS\_COMPILE=arm-linux-gnueabihf-" since it is 32-bit not 64-bit.
3. Do "make -f linux\_gcc.mak" to build the enclave.
4. On the destination machine (if Windows), apply the uuids.reg file
("reg.exe import uuids.reg") and reboot.

## Debugging

**For SGX:** You can use Visual Studio for debugging, including the SGX
simulator, that comes with the Intel SGX SDK.  Simply use the Debug
configuration in Visual Studio if you have SGX-capable hardware, or
the SGX-Simulation-Debug configuration in Visual Studio for software emulation.

**For TrustZone:** You can use a basic software emulation environment with OP-TEE.
Simply use the OPTEE-Simulation-Debug configuration in Visual Studio.
