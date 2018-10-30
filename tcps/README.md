# TCPS-SDK

This SDK is a framework library for building trusted applications on SGX
and TrustZone.

## Prerequisites

This library currently relies on having the Intel SGX SDK installed even if
developing
for TrustZone, since it requires using the sgx\_edger8r.exe utility that comes
with that SDK, and various header files.

The Intel SGX SDK can be downloaded for free at
[https://software.intel.com/en-us/sgx-sdk/download](https://software.intel.com/en-us/sgx-sdk/download).

This library also requires oeedger8r, which is part of the Open Enclave SDK.
However, a pre-built binary can also be directly downloaded:
* [Windows binary](https://oedownload.blob.core.windows.net/binaries/oeedger8r.exe)
* [Linux binary](https://oedownload.blob.core.windows.net/binaries/oeedger8r)

## Building the SDK itself

To build for Windows, open TCPS-SDK.sln with Visual Studio, and build
for the chosen platform (x86, x86, or ARM) and configuration.  This will
build any relevant binaries except for Trusted Applications that need to
run in OP-TEE (i.e., in TrustZone).

To build OP-TEE Trusted Applications, run the build\_optee.sh script from
a bash shell.

## Generating API calls between Trusted Apps and Untrusted Apps

To use this library, you must define your own
[EDL](https://software.intel.com/en-us/sgx-sdk-dev-reference-enclave-definition-language-file-syntax)
file that defines any APIs you want to
use, and use **oeedger8r** to generate code from it.
The same generated code will work equally with both SGX
and OP-TEE, as long as the EXE and TA use the right include paths and libs,
and the following additional code constraint is met:

OP-TEE only allows one thread per TA to be in an ecall (i.e., a call into
a TA from a regular app).  Even if it has an ocall (i.e., an out-call
back into the regular app) in progress, the ecall must complete before
another ecall can enter the TA.  SGX, on the other hand, would allow a
second ecall to enter.  So if you want them to function identically, apps
should wrap ecalls in the following mutex Acquire/Release calls:

```
oe_acquire_enclave_mutex(enclave);
sgxStatus = ecall_MyEcall(enclave, ...);
oe_acquire_enclave_mutex(enclave);
```

In the future, this will not be needed, but one can pass the 
OE\_ENCLAVE\_FLAG\_SERIALIZE\_ECALLS
flag when creating an enclave to automatically get this behavior.

## Include paths, preprocessor defines, and libraries

### SGX Enclave DLL

The SGX Enclave DLL should define **TRUSTED\_CODE** and **USE\_SGX** as
preprocessor symbols, link with **tcps\_t.lib** and have the following
additional include path:

* TCPS-SDK/Inc

### SGX Rich Application

The EXE should define **UNTRUSTED\_CODE** and **USE\_SGX** as preprocessor
symbols, link with **tcps\_u.lib** and have the following additional
include path:

* TCPS-SDK\Inc

### OP-TEE TA

The OP-TEE TA should define **TRUSTED\_CODE** and **USE\_OPTEE** as
preprocessor symbols, link with **tcps\_t.lib** and have the following
additional include paths, in this order (the order is important because
files in a deeper directory override files at higher levels with the
same filename):

* TCPS-SDK/Inc/optee/Trusted
* TCPS-SDK/Inc/optee
* TCPS-SDK/Inc

### OP-TEE Rich Application

The EXE should define **UNTRUSTED\_CODE** and **USE\_OPTEE** as
preprocessor symbols, link with **tcps\_u.lib** and have the following
additional include paths, in any order:

* TCPS-SDK\Inc
* TCPS-SDK\Inc\optee
* TCPS-SDK\Inc\optee\Untrusted

## TCPS Library APIs

The TCPS library provides support for a number of APIs that are not
available in SGX and/or OP-TEE.  For APIs that would normally be in some
standard C header (e.g., "stdio.h"), the convention is that instead of
including *token*.h, one would include (instead or in addition to the
one provided by SGX or OP-TEE if any), tcps\_*token*\_t.h for defines
common to both SGX and OP-TEE, or tcps\_*token*\_optee\_t.h for defines
unique to OP-TEE, since the Intel SGX SDK already provides more than OP-TEE
provides and such files provide the equivalent for OP-TEE.  For example,
the following such headers exist:

* tcps\_socket\_t.h
* tcps\_stdio\_t.h
* tcps\_stdlib\_t.h
* tcps\_string\_t.h
* tcps\_time\_t.h

Additional OP-TEE only headers that provide support already present in
SGX include:

* tcps\_ctype\_optee\_t.h
* tcps\_string\_optee\_t.h

If none of the above are needed, trusted code might need to include
tcps\_t.h (as well as the \*\_t.h file generated from the application's
EDL) to get basic definitions, but it should be pulled in automatically
if any of the above are included.

Untrusted code might need to include tcps\_u.h  (as well as the \*\_u.h
file generated from the application's EDL) to get basic definitions.

## Using this SDK

To use this SDK for a new application to run on both SGX and OP-TEE,
do the following.

For SGX:

1. In Visual Studio, add a new Visual C++ "Intel(R) SGX Enclave Project".
Make sure the Project Type is "Enclave" and the EDL File checkbox is checked.
2. Edit the _YourProjectName_.edl file, and add at least one public ecall
in the trusted{} section.  E.g., "public Tcps\_StatusCode ecall\_DoWork();"
Also, above (outside) the trusted{} section, add the following line:
* from "oebuffer.edl" import \*;
3. Update the command line for your EDL to use oeedger8r.
To do this, right click on the EDL file in the Solution Explorer window,
select "Properties"->"Configuration Properties"->"Custom Build Tool"->"General"
and edit the "Command Line" value for All Configurations and All Platforms.
Change it to "$(TcpsSdkDir)oeedger8r.exe" --trusted "%(FullPath)" --search-path "$(TcpsSdkDir)Inc;$(SGXSDKInstallPath)include" 
where $(TcpsSdkDir) is the path to the tcps subdirectory of this SDK.
4. In Visual Studio, add a new or existing Visual C++ project that will
build a normal application that will call the enclave.
5. Right click on the application project, select
"Intel(R) SGX Configuration"->"Import Enclave", and import the EDL
6. Right click on the application project, select "Properties"->"Debugging"
and change the "Debugger to launch" to "Intel(R) SGX Debugger".  You may
also want to change the Working Directory to the Output Directory of the
enclave project, where the enclave DLL will be placed.
7. Find the EDL file in the application project in the Solution Explorer window
and repeat step 3 here to update the command line to use oeedger8r.
8. In the enclave project, add implementations of the ecall(s) you added.
You will need to include <openenclave/enclave.h> and 
<_YourEDLFileName_\_t.h> for your ecalls.
9. In the "Configuration Properties"->"C/C++"->"Preprocessor", add
**TRUSTED\_CODE;USE\_SGX** to the enclave project, and
**UNTRUSTED\_CODE;USE\_SGX** to the application project, for
All Configurations and All Platforms
10. In the application project properties, under "Linker"->"Input", add
tcps\_u.lib;ws2\_32.lib;shell32.lib to the Additional Dependencies
(All Configurations, All Platforms).  Make sure you configure the
additional library directory as appropriate under
"Linker"->"General"->"Additional Library Directories".
11. If you want access to the full set of TCPS APIs from in the enclave,
in the enclave project properties, add tcps\_t.lib;sgx\_tstdc.lib to the
Additional Dependencies, and the path to tcps\_t.lib to the Additional
Library Directories.
12. Add code in the app to call oe\_create\__YourEDLFileName_\_enclave(),
any ecalls you added, and
oe\_terminate\_enclave().  You will need to #include <openenclave/host.h> 
and <_YourEDLFileName_\_u.h> for your ecalls.  Make sure you configure the
additional include directories as appropriate in your application project
Properties->"C/C++"->"General"->"Additional Include Directories".  Usually
this means you need to insert $(TcpsSdkDir)Inc path at the beginning.  See
the sample apps for an example.
13. In the enclave project, update the Additional Include Directories to
include $(TcpsSdkDir)External\RIoT\CyReP\cyrep

Then for OP-TEE:

1. Right click the solution, select "Configuration Manager", create an ARM
solution platform (if one doesn't already exist), and then create ARM
configurations of the application project (and tcps\_u if you include that
directly).  Copy the configuration from the existing Win32 one.  Don't do
this for the enclave project, as that needs to be built from the bash shell
rather than in Visual Studio.
2. Go back to the application project properties.  In the
"Configuration Properties"->"C/C++"->"Preprocessor" properties of the ARM 
platform for All Configurations, change **USE\_SGX** to **USE\_OPTEE**
3. Manually edit the application .vcxproj file to add the ability to
compile for ARM, since VS cannot do it from the UI.  To do so, add the
line "<WindowsSDKDesktopARMSupport\>true</WindowsSDKDesktopARMSupport\>"
to each ARM configuration property group.  (See the sample apps'
vcxproj file for examples.)
4. Copy the files from the Sample/Trusted/optee directory into your
enclave project, preferably into a optee subdirectory
5. Create a new GUID for the TA and fill it in in your linux\_gcc.mak,
user\_ta\_header\_defines.h, main.c, and uuids.reg files.  You can use the
guidgen.exe utility that comes with Visual Studio, or uuidgen (available
in a bash window), or
[https://www.uuidgenerator.net/](https://www.uuidgenerator.net/)
6. For any new source files you add to your enclave project in
Visual Studio, also add them to the sub.mk file in your optee subdirectory
7. In the application project properties, under "Linker"->"Input", add
rpcrt4.lib to the Additional Dependencies (All Configurations, ARM platform)
which is required for string-to-UUID conversion, and remove any sgx libs.
8. In the application project properties, update the Additional Include
Directories to insert the $(TcpsSdkDir)Inc\optee\Untrusted and
$(TcpsSdkDir)Inc\optee paths before the $(TcpsSdkDir)Inc path that you
added earlier.
8. Edit the sub.mk file in your optee subdirectory to change the "SampleTA"
in filenames to the name used with your .edl file.
9. On the destination machine, apply the uuids.reg file
("reg.exe import uuids.reg") and reboot.

## Debugging

For SGX: You can use Visual Studio for debugging, including the SGX
simulator, that comes with the Intel SGX SDK.  Simply use the Debug
configuration in Visual Studio if you have SGX-capable hardware, or
the DebugSimulation configuration in Visual Studio for software emulation.

For TrustZone: You can use a basic software emulation environment with OP-TEE
by creating and using a DebugMockOptee configuration in Visual Studio,
as follows...

1. Create a new configuration (say, for x86 and called DebugMockOptee)
based on the Debug configuration. A new configuration can be created
inside Visual Studio by right clicking on the solution, and accessing
the "Configuration Manager" screen.
2. Go to the application project properties.  In the
"Configuration Properties"->"C/C++"->"Preprocessor" for All Platforms
and for the DebugMockOptee configuration, change **USE\_SGX** to
**USE\_OPTEE;SIMULATE\_TEE**
3. Add mockoptee\_u.lib to the Additional Dependencies of your app and
remove any sgx libraries, for All Platforms for the DebugMockOptee
configuration. Your libs might look like this:
"tcps\_u.lib;ws2\_32.lib;rpcrt4.lib;shell32.lib;mockoptee\_u.lib"
4. Your app Additional Include Directories for DebugMockOptee
should include at least:
* $(TcpsSdkDir)Inc\optee\Untrusted
* $(TcpsSdkDir)Inc\optee
* $(TcpsSdkDir)Inc
* $(SGXSDKInstallPath)\include
5. In the "Configuration Properties->"Debugging", change Debugger to launch
back to Local Windows Debugger, and make the working directory be the
directory the enclave is built in (usually "$(OutDir)").
6. The same files that you build for OP-TEE should be built for
DebugMockOptee, so if you have files selectively built (e.g., if you
have C files marked as Exclude From Build for certain configurations),
update your configuration so that the same files get built, not any
SGX-specific ones.
7. Go to the TA project properties.  In the
"Configuration Properties"->"C/C++"->"Preprocessor" properties of the 
DebugMockOptee configuration for All Platforms, change **USE\_SGX** to
**USE\_OPTEE;SIMULATE\_TEE**
8. In the TA's "Configuration Properties"->"C/C++"->"General" properties of the
DebugMockOptee configuration for All Platforms, the Additional Include
Directories should NOT include $(SGXSDKInstallPath)include\tlibc or
$(SGXSDKInstallPath)include\libc++, and should include at least:
* $(TcpsSdkDir)External\RIoT\CyReP\cyrep
* $(TcpsSdkDir)Inc\optee\Trusted\Simulator
* $(TcpsSdkDir)Inc\optee\Trusted
* $(TcpsSdkDir)Inc\optee
* $(TcpsSdkDir)Inc
* $(SGXSDKInstallPath)include
* $(TcpsSdkDir)External\optee\_os\lib\libutee\include
* $(TcpsSdkDir)External\optee\_os\lib\libutils\ext\include
9. In the TA's "Configuration Properties"->"VC++ Directories" properties of the
DebugMockOptee configuration for All Platforms, change the Include Directories
and Library Directories from $(NoInherit) back to \<inherit from parent or
project defaults\>.
10. In the TA's "Configuration Properties"->"Linker"->"Input" in the
DebugMockOptee configuration for All Platforms, clear "Ignore All Default
Libraries", and add mockoptee\_t.lib to the Additional Dependencies of
your TA, and remove any sgx libs.  Your libs might look like this:
"tcps\_t.lib;mockoptee\_t.lib;kernel32.lib;vcruntime.lib;ucrtd.lib"
11. In the TA's "Configuration Properties"->"Build Events"->"Post-Build Event",
change the "Use in Build" to No for the DebugMockOptee configuration for all
Platforms.
12. In the TA's "Configuration Properties"->"General" section in the
DebugMockOptee configuration for All Platforms, change the Target Name
to be the TA's UUID (without curly braces).
