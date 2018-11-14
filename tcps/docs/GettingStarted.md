Getting Started with the Open Enclave SDK
=========================================

## Prerequisites

This SDK currently relies on having the Intel SGX SDK installed even if
developing
for TrustZone, since it requires using the sgx\_edger8r.exe utility that comes
with that SDK, and various header files.

The Intel SGX SDK can be downloaded for free at
[https://software.intel.com/en-us/sgx-sdk/download](https://software.intel.com/en-us/sgx-sdk/download).

Building applications using this SDK also requires oeedger8r, the source for
which is part of this SDK.
However, a pre-built binary can also be directly downloaded:
* [Windows binary](https://oedownload.blob.core.windows.net/binaries/oeedger8r.exe)
* [Linux binary](https://oedownload.blob.core.windows.net/binaries/oeedger8r)

## Building the SDK itself

To build for Windows, open OpenEnclave.sln with Visual Studio, and build
for the chosen platform (x86, x86, or ARM) and configuration.  This will
build any relevant binaries except for Trusted Applications that need to
run on OP-TEE (i.e., in TrustZone).

To build OP-TEE Trusted Applications, run the build\_optee.sh script from
a bash shell (in Linux, or in 
[Ubuntu on Windows](https://docs.microsoft.com/en-us/windows/wsl/install-win10)).

## Generating API calls between Trusted Apps and Untrusted Apps

To use this SDK, you must define your own
[EDL](https://software.intel.com/en-us/sgx-sdk-dev-reference-enclave-definition-language-file-syntax)
file that defines any APIs you want to
use, and use **oeedger8r** to generate code from it.
The same generated code will work equally with both SGX
and OP-TEE, as long as the Untrusted App and the Trusted App both use the right include paths and libs,
and the following additional code constraint is met:

OP-TEE only allows one thread per TA to be in an ECALL (i.e., a call into
a TA from a regular app).  Even if it has an OCALL (i.e., an out-call
back into the regular app) in progress, the ECALL must complete before
another ECALL can enter the TA.  SGX, on the other hand, would allow a
second ECALL to enter.  So if you want them to function identically, apps
should pass the OE\_ENCLAVE\_FLAG\_SERIALIZE\_ECALLS
flag when creating an enclave to automatically get the OP-TEE like behavior
for both SGX and TrustZone.

## Include paths, preprocessor defines, and libraries

### SGX Enclave DLL

The SGX Enclave DLL should link with **oeenclave.lib** and have the following
additional include paths:

* $(OESdkDir)tcps\include\sgx\Trusted
* $(OESdkDir)tcps\include

To use socket APIs, the SGX Enclave DLL should link with **oesocket_enc.lib**.
See the sockets sample for an example.

### SGX Rich Application

The EXE should link with **oehost.lib** and have the following additional
include path:

* $(OESdkDir)tcps\include

To allow the SGX Enclave DLL to use socket APIs, the EXE should link with **oesocket_host.lib**.
See the sockets sample for an example.

### OP-TEE TA

The OP-TEE TA should link with **liboeenclave** and have the following
additional include paths, in this order (the order is important because
files in a deeper directory override files at higher levels with the
same filename):

* $(OESdkDir)tcps/include/optee/Trusted
* $(OESdkDir)tcps/include/optee
* $(OESdkDir)tcps/include

To use socket APIs, the OP-TEE TA should link with **liboesocket_enc**.
See the sockets sample for an example.

### OP-TEE Rich Application

The EXE should link with **oehost.lib** and have the following
additional include paths, in any order:

* $(OESdkDir)tcps\include
* $(OESdkDir)tcps\include\optee
* $(OESdkDir)tcps\include\optee\Untrusted

To allow the OP-TEE TA to use socket APIs, the EXE should link with **oesocket_host.lib**.
See the sockets sample for an example.

## Open Enclave APIs

This SDK implements the Open Enclave APIs covered in
[API docs](https://ms-iot.github.io/openenclave/api/files.html).

This SDK also provides support for a number of APIs that are not
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

If none of the above are needed, trusted code might need to #include
<openenclave/enclave.h> (as well as the \*\_t.h file generated from your application's
EDL file) to get basic definitions, but it should be pulled in automatically
if any of the above are included.

Untrusted code might need to #include <openenclave/host.h>  (as well as the \*\_u.h
file generated from your application's EDL file) to get basic definitions.

## Using this SDK from Windows

To use this SDK for a new application to run on both SGX and OP-TEE,
do the following.

**To build for SGX:**

1. In Visual Studio, add a new Visual C++ "Intel(R) SGX Enclave Project".
Make sure the Project Type is "Enclave" and the EDL File checkbox is checked.
2. Edit the _YourProjectName_.edl file, and add at least one public ECALL
in the trusted{} section.  E.g., "public void ecall\_DoWork();"
Also, to use stdio APIs such as printf, above (outside) the trusted{} section, add the following line:
* from "openenclave/stdio.edl" import *;
3. Update the command line for your EDL to use oeedger8r.
To do this, right click on the EDL file in the Solution Explorer window,
select "Properties"->"Configuration Properties"->"Custom Build Tool"->"General"
and edit the "Command Line" value for All Configurations and All Platforms.
Change it to "$(TcpsDir)oeedger8r.exe" --trusted "%(FullPath)" --search-path "$(TcpsDir)include;$(SGXSDKInstallPath)include" 
where $(TcpsDir) is the path to the tcps subdirectory of this SDK.
4. In Visual Studio, add a new or existing Visual C++ project that will
build a normal application that will make ECALLs into your enclave.
5. Right click on your application project, select
"Intel(R) SGX Configuration"->"Import Enclave", and import the EDL
6. Right click on your application project, select "Properties"->"Debugging"
and change the "Debugger to launch" to "Intel(R) SGX Debugger".  You may
also want to change the Working Directory to the Output Directory of the
enclave project, where your enclave DLL will be placed.
7. Find the EDL file in your application project in the Solution Explorer window
and repeat step 3 here to update the command line to use oeedger8r.
8. In your enclave project, add implementations of the ECALL(s) you added.
You will need to #include <openenclave/enclave.h> and <_YourEDLFileName_\_t.h> for your ECALLs.
9. In your application project properties, under "Linker"->"Input", add
oehost.lib;ws2\_32.lib;shell32.lib to the Additional Dependencies
(All Configurations, All Platforms).  Make sure you configure the
additional library directory as appropriate under
"Linker"->"General"->"Additional Library Directories".
10. If you want access to the full set of Open Enclave APIs from within your enclave,
in your enclave project properties, add oeenclave.lib;sgx\_tstdc.lib to the
Additional Dependencies, and the path to oeenclave.lib to the Additional
Library Directories.
11. Add code in your app to call oe\_create\__YourEDLFileName_\_enclave(),
any ECALLs you added, and
oe\_terminate\_enclave().  You will need to #include <openenclave/host.h> 
and <_YourEDLFileName_\_u.h> for your ECALLs.  Make sure you configure the
additional include directories as appropriate in your application project
Properties->"C/C++"->"General"->"Additional Include Directories".  Usually
this means you need to insert "$(TcpsDir)include;$(TcpsDir)include\sgx\Trusted;"
at the beginning.  See the sample apps for an example.
12. In your enclave project, update the Additional Include Directories to
include $(OESdkDir)3rdparty\RIoT\CyReP\cyrep

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
3. Copy the files from the samples/Trusted/optee directory into your
enclave project, preferably into an "optee" subdirectory
4. Create a new GUID for your TA and fill it in in your linux\_gcc.mak,
user\_ta\_header\_defines.h, main.c, and uuids.reg files.  You can use the
guidgen.exe utility that comes with Visual Studio, or uuidgen (available
in a bash window), or
[https://www.uuidgenerator.net/](https://www.uuidgenerator.net/)
5. For any new source files you add to your enclave project in
Visual Studio, also add them to the sub.mk file in your optee subdirectory
6. In your application project properties, under "Linker"->"Input", add
rpcrt4.lib to the Additional Dependencies (All Configurations, ARM platform)
which is required for string-to-UUID conversion, and remove any sgx libs.
7. In your application project properties, update the Additional Include
Directories to insert the $(TcpsDir)include\optee\Untrusted and
$(TcpsDir)include\optee paths before the $(TcpsDir)include path that you
added earlier.
8. Edit the sub.mk file in your optee subdirectory to change the "SampleTA"
in filenames to the name used with your .edl file.
9. On the destination machine, apply the uuids.reg file
("reg.exe import uuids.reg") and reboot.

## Debugging

**For SGX:** You can use Visual Studio for debugging, including the SGX
simulator, that comes with the Intel SGX SDK.  Simply use the Debug
configuration in Visual Studio if you have SGX-capable hardware, or
the DebugSimulation configuration in Visual Studio for software emulation.

**For TrustZone:** You can use a basic software emulation environment with OP-TEE
by creating and using a DebugOpteeSimulation configuration in Visual Studio,
as follows...

1. Create a new configuration (say, for x86 and called DebugOpteeSimulation)
based on the Debug configuration. A new configuration can be created
inside Visual Studio by right clicking on the solution, and accessing
the "Configuration Manager" screen.
2. Go to your application project properties.  In the
"Configuration Properties"->"C/C++"->"Preprocessor" properties for All Platforms
for the DebugOpteeSimulation configuration, add
**OE\_SIMULATE\_OPTEE**.  Then do the same for your enclave project.
3. Add oehost\_opteesim.lib to the Additional Dependencies of your app and
remove any sgx libraries, for All Platforms for the DebugOpteeSimulation
configuration. Your libs might look like this:
"oehost.lib;ws2\_32.lib;rpcrt4.lib;shell32.lib;oehost\_opteesim.lib"
4. Your app Additional Include Directories for DebugOpteeSimulation
should include at least:
* $(TcpsDir)include\optee\Untrusted
* $(TcpsDir)include\optee
* $(TcpsDir)include
* $(SGXSDKInstallPath)\include
5. In the "Configuration Properties->"Debugging", change Debugger to launch
back to Local Windows Debugger, and make the working directory be the
directory your enclave is built in (usually "$(OutDir)").
6. The same files that you build for OP-TEE should be built for
DebugOpteeSimulation, so if you have files selectively built (e.g., if you
have C files marked as Exclude From Build for certain configurations),
update your configuration so that the same files get built, not any
SGX-specific ones.
7. In your TA's "Configuration Properties"->"C/C++"->"General" properties of the
DebugOpteeSimulation configuration for All Platforms, the Additional Include
Directories should NOT include $(SGXSDKInstallPath)include\tlibc or
$(SGXSDKInstallPath)include\libc++, and should include at least:
* $(OESdkDir)3rdparty\RIoT\CyReP\cyrep
* $(TcpsDir)include\optee\Trusted\Simulator
* $(TcpsDir)include\optee\Trusted
* $(TcpsDir)include\optee
* $(TcpsDir)include
* $(SGXSDKInstallPath)include
* $(OESdkDir)3rdparty\optee\_os\lib\libutee\include
* $(OESdkDir)3rdparty\optee\_os\lib\libutils\ext\include
8. In your TA's "Configuration Properties"->"VC++ Directories" properties of the
DebugOpteeSimulation configuration for All Platforms, change the Include Directories
and Library Directories from $(NoInherit) back to \<inherit from parent or
project defaults\>.
9. In your TA's "Configuration Properties"->"Linker"->"Input" in the
DebugOpteeSimulation configuration for All Platforms, clear "Ignore All Default
Libraries", and add oeenclave\_opteesim.lib to the Additional Dependencies of
your TA, and remove any sgx libs.  Your libs might look like this:
"oeenclave.lib;oeenclave\_opteesim.lib;kernel32.lib;vcruntime.lib;ucrtd.lib"
10. In your TA's "Configuration Properties"->"Build Events"->"Post-Build Event",
change the "Use in Build" to No for the DebugOpteeSimulation configuration for all
Platforms.
11. In your TA's "Configuration Properties"->"General" section in the
DebugOpteeSimulation configuration for All Platforms, change the Target Name
to be your TA's UUID (without curly braces).
