Samples
-------

Find the samples under **share/openenclave/samples/** of the installation.

Change to the new samples directory and build and run the samples.

```
$ cd ~/openenclave/share/openenclave/samples
$ sh test-samples.sh
```

If these samples run without an error, then Open Enclave is installed and working correctly.


Developing a simple enclave (echo)
----------------------------------

This chapter shows how to develop a simple enclave called echo. The next
chapter explains how to use this enclave in a host application. This example
is included in the installed samples directory (see
\<install_prefix\>/openenclave/share/openenclave/samples/hello/).

### The ECALL

The echo enclave implements a single ECALL named EnclaveEcho(), which is
called by the host (in the next chapter). This function has the following
signature.

```
OE_ECALL void EnclaveEcho(void* args);
```

The args parameter can be whatever the host and the enclave agree on. In this
case args is a pointer to a zero-terminated string in host memory. The
OE_ECALL macro exports the function and injects it into a special section
(.ecall) in the ELF image. When the host loads the enclave, it builds a table
of all ECALLs exported by the enclave.

### The Echo enclave Listing

Here’s the full listing for the echo enclave (enc/enc.c):

```
#include <openenclave/enclave.h>

OE_ECALL void EnclaveEcho(void* args)
{
    oe_call_host("HostEcho", args);
}
```

Notice EnclaveEcho() performs an OCALL, calling the host’s HostEcho()
function with the same arguments.

### Enclave build collateral

The samples provides cmake helper includes under samples/cmake/cmake/
simplifying Open Enclave application writing. **add_enclave_executable.cmake**
provides the **add_enclave_executable()** function. It extends CMake's
**add_executable()** by adding the intrinsic target (oecore) and also
signing the enclave. For the echo sample, this ***CMakeLists.txt*** suffices:

```
include(add_enclave_executable)
add_enclave_executable(samples-echoenc echo.conf private.pem
    enc.c
    )
```

The **echo.conf** argument is the name of a configuration file that defines
enclave settings, such as stack size, heap size, and the maximum number of
threads (TCSs). Here is the echo sample:

```
# echo.conf
Debug=1
NumHeapPages=1024
NumStackPages=1024
NumTCS=2
ProductID=1
SecurityVersion=1
```

The **private.pem** argument is a private RSA key used to sign the enclave,
here included with the sample. To generate a self-signed private key yourself,
use OpenSSL as follows.

```
# openssl genrsa -out private.pem -3 3072
```

Then the public key can be generated from this key as follows.

```
# openssl rsa -in private.pem -pubout -out public.pem
```

Developing a simple host (echohost)
-----------------------------------

Next, we develop a host to run the echoenc.signed.so enclave that we developed
in the previous chapter. The listing from samples/cmake/echo/host follows.

```
#include <openenclave/host.h>
#include <stdio.h>

OE_OCALL void HostEcho(void* args)
{
    if (args)
    {
        const char* str = (const char*)args;
        printf("%s\n", str);
    }
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    result = oe_create_enclave(
        argv[1],
        OE_ENCLAVE_TYPE_SGX,
        OE_ENCLAVE_FLAG_DEBUG,
        NULL,
        0,
        &enclave);

    if (result != OE_OK)
    {
        fprintf(stderr, "%s: oe_create_enclave(): %u\n", argv[0], result);
        return 1;
    }

    result = oe_call_enclave(enclave, "EnclaveEcho", "Hello");
    if (result != OE_OK)
    {
        fprintf(stderr, "%s: oe_call_enclave(): %u\n", argv[0], result);
        return 1;
    }

    oe_terminate_enclave(enclave);

    return 0;
}
```

This host performs the following tasks:

- Defines an OCALL: HostEcho()
- Instantiates an enclave: oe_create_enclave()
- Calls into the enclave: oe_call_enclave()
- Terminates the enclave: oe_terminate_enclave()

### Host build collateral

The ***CMakeLists.txt*** is rather straight-forward, though note the
**oehostapp** link target in the add_executable() call:

```
add_executable(samples-echohost host.c)
target_link_libraries(samples-echohost oehostapp)
```

The additional target instructs CMake to provide the open enclave includes and
host libraries (via oehost), as well as the proper linker flags for the host
OCall targets to be resolved.

Completing the echo sample
--------------------------

In the project file **samples/cmake/CMakeLists.txt**, note the line:
```
include(${OE_PREFIX}/share/openenclave/openenclave.cmake)
```

This sources the CMake include providing the Open Enclave targets.

Build the samples, e.g. in a subdirectory under samples/cmake:
```
samples/cmake$ mkdir build && cd build
samples/cmake/build$ cmake .. -DOE_PREFIX=../../../.. && make
```

After building, we are ready to run the samples:

```
samples/cmake/build$ ctest
```

------------------------------------------------

Other build systems
-------------------

If you are not using CMake for your project, the Makefile samples under
***samples/*** provide guidance on the necessary includes, libraries, and
flag definitions.

Specifically, the Open Enclave includes for the intrinsics are located under
<PREFIX>/include/openenclave (or via the **OE_INCLUDEDIR** make variable when
using the make include installed under <PREFIX>/share/openenclave/config.mak).

Necessary gcc compiler flags for enclave code are:
```
CFLAGS=-nostdinc -fPIC
```

Necessary gcc linker flags for an enclave are:
```
LDFLAGS=\
    -nostdlib \
    -nodefaultlibs \
    -nostartfiles \
    -Wl,--no-undefined \
    -Wl,-Bstatic \
    -Wl,-Bsymbolic \
    -Wl,--export-dynamic \
    -Wl,-pie \
```

The entry point for the enclave image is **_start()**. The linker stores 
the virtual address of the **_start()** function in the ELF header 
(Elf64_Ehdr.e_entry) of the resulting image. When the enclave is instantiated 
by the host, this entry point is copied to each TCS (Thread Control Structure) 
in the image. When the host invokes the SGX EENTER instruction on a TCS, the 
hardware fetches the entry point from the TCS and jumps to that address and 
the **_start()** function begins to execute.

The necessary enclave library contains the enclave intrinsics, including the
_start() entry point. Note that the echo sample uses neither a C nor C++
runtime library. Other samples will show how these are used.

```
LIBRARIES = -L${OE_LIBDIR}/openenclave/enclave -loecore
```

To sign the enclave, use the **oesign** tool. This tool takes the following
parameters.

```
$ oesign

Usage: oesign ENCLAVE CONFFILE KEYFILE
```

The CONFFILE argument is the name of a configuration file that defines enclave
settings, and the KEYFILE argument is a private RSA key used to sign the
enclave. See the CMake section for details on these files.


### Debugging the enclave

We can't use GDB directly to debug enclave application since it doesn't understand enclave yet.
Open Enclave includes a GDB plugin to help developers to debug enclaves that is developed using this SDK.

Note: the enclave must be created with debug opt-in flag, otherwise debugger can't work since it can't read the enclave memory.
The default sample enclave is created with debug flag, refer to:

```
result = oe_create_enclave(
        argv[1],
        OE_ENCLAVE_TYPE_SGX,
        OE_ENCLAVE_FLAG_DEBUG,
        NULL,
        0,
        &enclave);
```

This flag (OE_ENCLAVE_FLAG_DEBUG) should only be set in development phase. It needs to be removed for a production enclave.

The debugger is installed at <install_prefix>/bin/oe-gdb. The usage is same with GDB, for example: the following command will
launch the simple enclave application under debugger:

```
# /opt/openenclave/bin/oe-gdb -arg ./host/echohost ./enc/echoenc.signed.so
```

After the enclave application is loaded, you can use b to set breakpoint, bt to check stack etc.
