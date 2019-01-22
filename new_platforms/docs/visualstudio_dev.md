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
1. In Visual Studio, add a new Visual C++ "Open Enclave TEE Project".
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


**Then to build for OP-TEE:**

1. Right click the solution, select "Configuration Manager", create an ARM
solution platform (if one doesn't already exist), and then create ARM
configurations of your application project (and oehost if you include that
directly).  Copy the configuration from the existing Win32 one.  Don't do
this for your enclave project, as that needs to be built from a bash shell
rather than in Visual Studio.
2. Manually edit your application .vcxproj file to add the ability to
compile for ARM, since Visual Studio cannot do it from the UI.  To do so, add the
line "<WindowsSDKDesktopARMSupport\>true</WindowsSDKDesktopARMSupport\>"
to each ARM configuration property group.  (See the sample apps'
vcxproj file for examples.)
3. For any new source files you add to your enclave project in
Visual Studio, also add them to the sub.mk file in your optee subdirectory
4. In your application project properties, under "Linker"->"Input", add
rpcrt4.lib to the Additional Dependencies (All Configurations, ARM platform)
which is required for string-to-UUID conversion, and remove any sgx libs.
5. In your application project properties, update the Additional Include
Directories to insert the $(NewPlatformsDir)include\optee\host and
$(NewPlatformsDir)include\optee paths before the $(NewPlatformsDir)include path that you
added earlier.
6. On the destination machine, apply the uuids.reg file
("reg.exe import uuids.reg") and reboot.

## Debugging

(Note: the information about the OPTEE-Simulation-Debug
configuration is out of date and will be updated shortly.)

**For SGX:** You can use Visual Studio for debugging, including the SGX
simulator, that comes with the Intel SGX SDK.  Simply use the Debug
configuration in Visual Studio if you have SGX-capable hardware, or
the SGX-Simulation-Debug configuration in Visual Studio for software emulation.

**For TrustZone:** You can use a basic software emulation environment with OP-TEE
by creating and using a OPTEE-Simulation-Debug configuration in Visual Studio,
as follows...

1. Create a new configuration (say, for x86 and called OPTEE-Simulation-Debug)
based on the Debug configuration. A new configuration can be created
inside Visual Studio by right clicking on the solution, and accessing
the "Configuration Manager" screen.
2. In the "Configuration Properties->"Debugging", make the working directory
be the directory your enclave is built in (usually "$(OutDir)").
