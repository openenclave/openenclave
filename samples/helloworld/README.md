
# The helloworld sample

- Written in C
- Minimum code needed for an Open Enclave app
- Help understand the basic components an OE(Open Enclave) application
- Demonstrate how to build, sign, and run an OE image
- Demonstrate how to optionally apply LVI mitigation to enclave code
- Also runs in OE simulation mode

## Prerequisites

- Use an OE SDK-supported machine or development environment (like Intel SGX).
- Install the OE SDK package and dependencies for your environment. Install the OE SDK package and dependencies for your environment. See the [Getting Started documentation](/../../../openenclave#getting-started) to find OS-specific installation instructions.
- Read the common sample information page to learn how to prepare the sample on [Linux](../README_Linux.md#building-open-enclave-sdk-samples-on-linux) and [Windows](../README_Windows.md#building-open-enclave-sdk-samples-on-windows).

## About the helloworld sample

This sample is about as simple as you can get regarding creating and calling into an enclave. In this sample you will see:

- The host creates an enclave
- The host calls a simple function in the enclave
- The enclave function prints a message and then calls a simple function back in the host
- The host function prints a message before returning to the enclave
- The enclave function returns back to the host
- The enclave is terminated

This sample uses the Open Enclave SDK `oeedger8r` tool to generate marshaling code necessary to call functions between the enclave
and the host. For more information on using the Open Enclave oeedger8r tool refer to
[Getting started with the Open Enclave edger8r](https://github.com/openenclave/openenclave/tree/master/docs/GettingStartedDocs/Edger8rGettingStarted.md).

First we need to define the functions we want to call between the enclave and host. To do this we create a `helloworld.edl` file:

```edl
enclave {
    trusted {
        public void enclave_helloworld();

    };

    untrusted {
        void host_helloworld();
    };
};
```

In this `helloworld.edl` file we define two different functions.

```c
public void enclave_helloworld();
```

This method will be implemented inside the trusted enclave itself and the untrusted host will call it. For the host to be able to call this function the host needs to call through the Open Enclave SDK to transition from the untrusted host into the trusted enclave. To help with this the `oeedger8r` tool generates some marshaling code in the host directory with the same signature as the function in the enclave, with the addition of an enclave handle so the SDK knows which enclave will execute the code.

```c
void host_helloworld();
```

The reverse is also true for functions defined in the untrusted host that the trusted enclave needs to call into. The untrusted host will implement this function and the `oeedger8r` tool generates some marshaling code in the enclave directory with the same signature as the function in the host.

To generate the functions with the marshaling code the `oeedger8r` is called in both the host and enclave directories from their Makefiles:

To generate the marshaling code the untrusted host uses to call into the trusted enclave the following command is run:

```bash
oeedger8r ../helloworld.edl --untrusted
```

This command compiles the `helloworld.edl` file and generates the following files within the host directory:

| file | description |
|---|---|
| host/helloworld_args.h | Defines the parameters that are passed to all functions defined in the edl file |
| host/helloworld_u.c | Contains the `enclave_helloworld()` function with the marshaling code to call into the enclave version of the `enclave_helloworld()` function |
| host/helloworld_u.h | Function prototype for `enclave_helloworld()` function |

To generate the marshaling code the trusted enclave uses to call into the untrusted host the following command is run:

```bash
oeedger8r ../helloworld.edl --trusted
```

| file | description |
|---|---|
| enclave/helloworld_args.h | Defines the parameters that are passed to all functions defined in the edl file |
| enclave/helloworld_t.c | Contains the `host_helloworld()` function with the marshaling code to call into the host version of the `host_helloworld()` function |
| enclave/helloworld_t.h | function prototype for `host_helloworld()` function |

The Makefile in the root of this sample directory has three rules

- build: Calls into the Makefiles in the host and enclave directories to build
- clean: Calls in to the Makefiles in the host and enclave directories to clean all generated files
- run: Runs the generated host executable, passing the signed enclave executable as a parameter

```make
build:
        $(MAKE) -C enclave
        $(MAKE) -C host

clean:
        $(MAKE) -C enclave clean
        $(MAKE) -C host clean

run:
        host/helloworldhost ./enclave/helloworldenc.signed
```

Build the project with the following command:

```bash
make build
```

Clean the project with the following command:

```bash
make clean
```

Run the built sample with the following command:

```bash
make run
```

## Enclave component

This section shows how to develop and build a simple enclave called helloworld.

### Develop an enclave

An enclave exposes its functionality to the host application in the form of a set of trusted methods that are defined in the `helloworld.edl` file and implemented within the enclave project.

The helloworld sample implements a single function named `enclave_helloworld` which is called by the host. All it does is print out a message and then call back to the host. No parameters are passed in this sample for simplicity.

The full source for the enclave implementation is here: [helloworld/enclave/enc.c](enclave/enc.c)

```c
#include <stdio.h>

// Include the trusted helloworld header that is generated
// during the build. This file is generated by calling the
// sdk tool oeedger8r against the helloworld.edl file.
#include "helloworld_t.h"

// This is the function that the host calls. It prints
// a message in the enclave before calling back out to
// the host to print a message from there too.
void enclave_helloworld()
{
    // Print a message from the enclave. Note that this
    // does not directly call fprintf, but calls into the
    // host and calls fprintf from there. This is because
    // the fprintf function is not part of the enclave
    // as it requires support from the kernel.
    fprintf(stdout, "Hello world from the enclave\n");

    // Call back into the host
    oe_result_t result = host_helloworld();
    if (result != OE_OK)
    {
        fprintf(stderr, "Call to host_helloworld failed: result=%u (%s)\n", result,
         oe_result_str(result));
    }
}
```

Each line will now be described in turn.

```c
#include <stdio.h>
```

An enclave library will be loaded into and run inside a host application which is a user-mode process. To keep the [trusted computing base](https://en.wikipedia.org/wiki/Trusted_computing_base) small, the decision was made to make only a specific set of APIs available to an enclave library. A complete list of APIs available to an enclave library can be found [here](https://github.com/openenclave/openenclave/tree/master/docs/GettingStartedDocs/APIs_and_Libs.md)

The `stdio.h` header file is included in this sample because we are calling the CRT function `fprintf` to print a message on the screen. However this function has a dependency on the kernel to print a message on the screen so this code cannot execute within the enclave itself. Instead this function marshals the call through to the host to carry out the call on the enclaves behalf. Only a subset of the CRT is made available through this open enclave library.

 ```c
void enclave_helloworld()
```

An enclave exposes its functionality via a set of methods defined in the `helloworld.edl` file and implemented here. The only implemented function in the enclave in this sample is `enclave_helloworld`.

```c
fprintf(stdout, "Hello world from the enclave\n");
```

As described above, this call to print a message on the screen marshals the call out of the enclave and back to the untrusted host to print the message.

```c
oe_result_t result = host_helloworld();
if (result != OE_OK)
{
    fprintf(stderr, "Call to host_helloworld failed: result=%u (%s)\n", result, oe_result_str(result));
}
```

This calls the marshaling function that is generated from the `helloworld.edl` file which in turn calls into the function within the host. Even though the `host_helloworld()` function is a `void` this call can still fail within the marshaling code itself and so we should always validate it. If `host_helloworld()` were to return a value, it would actually be passed back as an out parameter of the function.

### Build and sign an enclave

As mentioned in [how-to-build-and-run-samples](../README.md#how-to-build-and-run-samples), make files are provided for each sample. You can build the whole sample by running `make build` from the sample root, or you can build the enclave and host separately by running `make build` in each directory.

The following enclave files come with the sample:

| File | Description |
| --- | --- |
| enc.c | Source code for the enclave `enclave_helloworld` function |
| Makefile | Makefile used to build the enclave |
| helloworld.conf | Configuration parameters for the enclave |

The following files are generated during the build.

| File | Description |
| --- | --- |
| enc.o | Compiled source file for enc.c |
| helloworldenc | built and linked enclave executable |
| helloworldenc.signed | signed version of the enclave executable |
| helloworld_args.h | Defines the parameters that are passed to all functions defined in the edl file |
| helloworld_t.c | Contains the `host_helloworld()` function with the marshaling code to call into the host version of the `host_helloworld()` function |
| helloworld_t.h | function prototype for `host_helloworld()` function |
| helloworld_t.o | compiled marshaling code for helloworld_t.c |
| private.pem | generated signature used for signing the executable |
| public.pem | generated signature used for signing the executable |

Only the signed version of the enclave `helloworldenc.signed` is loadable on Linux as enclaves are required to be digitally signed.

#### Under the hood for the `make build` operation

Here is a listing of key components in the helloworld/enclave/Makefile. Also see the [complete listing](enclave/Makefile).

```make
include ../../config.mk

CFLAGS=$(shell pkg-config oeenclave-$(COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oeenclave-$(COMPILER) --libs)

all:
	$(MAKE) build
	$(MAKE) keys
	$(MAKE) sign

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../helloworld.edl --trusted
	$(CC) -g -c $(CFLAGS) -DOE_API_VERSION=2 enc.c -o enc.o
	$(CC) -g -c $(CFLAGS) -DOE_API_VERSION=2 helloworld_t.c -o helloworld_t.o
	$(CC) -o helloworldenc helloworld_t.o enc.o $(LDFLAGS)

sign:
	oesign sign -e helloworldenc -c helloworld.conf -k private.pem

clean:
	rm -f enc.o helloworldenc helloworldenc.signed private.pem public.pem helloworld_t.o helloworld_t.h helloworld_t.c helloworld_args.h

keys:
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem
```

All OE samples use the `pkg-config` tool for building.

If you are interested in its details, you can find OE pkg-config pc files in package_installtation_destination/share/pkgconfig.

For example: /opt/openenclave/share/pkgconfig

##### Build

The Makefile's `build` target is for compiling enclave source code and linking its library with its dependent libraries (in the following order):

- oeenclave
- mbedx509
- mbedcrypto
- oelibc
- oesyscall
- oecore

When compiling with LVI mitigation, it links against the LVI-mitigated versions of those libraries instead:

- oeenclave-lvi-cfg
- mbedx509-lvi-cfg
- mbedcrypto-lvi-cfg
- oelibc-lvi-cfg
- oesyscall-lvi-cfg
- oecore-lvi-cfg

`helloworldenc` is the resulting enclave executable (unsigned).

##### Sign

The OE SDK comes with a signing tool called `oesign` for digitally signing an enclave library. Run `oesign --help` for the usage. For this sample we use the `openssl` command in the `keys` rule to generate the signature, then we sign with the `oesign` tool using the generated signatures.

The signing process also reads the `helloworld.conf` file which describes important parameters associated with with enclave.

```conf
Debug=1
NumHeapPages=1024
NumStackPages=1024
NumTCS=1
ProductID=1
SecurityVersion=1
```

These parameters are described in the [Enclave Building and Signing](https://github.com/openenclave/openenclave/tree/master/docs/GettingStartedDocs/buildandsign.md#signing-the-enclave) document.

## Host Application

The host process is what drives the enclave app. It is responsible for managing the lifetime of the enclave and invoking enclave methods, but should be considered an untrusted component that is never allowed to handle plaintext secrets intended for the enclave.

In this section we will cover how to develop a host to load and run the helloworld enclave we built above.

### Develop a host

There are relatively fewer restrictions on developing a host application compared to authoring an enclave.
In general, you are free to link your choice of additional libraries into the host application. A part of
a typical host application job is to manage the life cycle of an enclave. Open Enclave SDK provides
an enclave host runtime, with enclave management functions exposed through [openenclave/host.h](https://openenclave.github.io/openenclave/api/host_8h.html).

The full source for the host implementation is here: [helloworld/host/host.c](host/host.c)

```c
#include <openenclave/host.h>
#include <stdio.h>

// Include the untrusted helloworld header that is generated
// during the build. This file is generated by calling the
// sdk tool oeedger8r against the helloworld.edl file.
#include "helloworld_u.h"

// This is the function that the enclave will call back into to
// print a message.
void host_helloworld()
{
    fprintf(stdout, "Enclave called into host to print: Hello World!\n");
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

    // Create the enclave by calling oeedger8r generated function.
    result = oe_create_helloworld_enclave(
        argv[1], OE_ENCLAVE_TYPE_AUTO, OE_ENCLAVE_FLAG_DEBUG, NULL, 0, &enclave);
    if (result != OE_OK)
    {
        fprintf(stderr, "oe_create_helloworld_enclave(): result=%u (%s)\n", result, oe_result_str(result));
        goto exit;
    }

    // Call into the enclave
    result = enclave_helloworld(enclave);
    if (result != OE_OK)
    {
        fprintf(stderr, "calling into enclave_helloworld failed: result=%u (%s)\n", result, oe_result_str(result));
        goto exit;
    }

    ret = 0;

exit:
    //Clean up the enclave if we created one
    if (enclave)
        oe_terminate_enclave(enclave);

    return ret;
}
```

Each line will now be described in turn.

```c
#include <openenclave/host.h>
```

Includes the header for the Open Enclave functions used in this file, (e.g `oe_terminate_enclave`).

```c
#include <stdio.h>
```

Includes the standard CRT libraries. Unlike the enclave implementation, which includes a special enclave version of the stdio library that marshals APIs to the host, the host is not protected, so uses all the normal C libraries and functions.

```c
void host_helloworld()
{
    fprintf(stdout, "Enclave called into host to print: Hello World!\n");
}
```

This is the actual host function that the enclave calls into. The function is defined in the `helloworld.edl` file and implemented here.

```c
int main(int argc, const char* argv[])
```

The host is the application that creates and calls into the enclave, so this host is a normal C executable with a standard `main` function.

```c
result = oe_create_helloworld_enclave(
    argv[1], OE_ENCLAVE_TYPE_AUTO, OE_ENCLAVE_FLAG_DEBUG, NULL, 0, &enclave);
```

This `oe_create_helloworld_enclave` function is generated by oeedger8r.
This function creates an enclave for use in the host process. This includes:
- Allocating the enclave address space.
- Loading the enclave code and data from its library file into that address space.
- Setting up the enclave environment, including the enclave heap and data structures for each enclave thread.
- Measuring the resulting enclave identity and ensuring it matches the enclave signature.
- Initializing the enclave so that it is ready to be called from the host.

The helloworld sample creates an enclave by calling `oe_create_helloworld_enclave` with the path to the signed enclave library file, which happens to be passed as the first parameter to the launching application.

The `OE_ENCLAVE_FLAG_DEBUG` flag allows the enclave to be created without the enclave binary being signed. It also gives a developer permission to debug the process and get access to enclave memory. What this means is ** DO NOT SHIP CODE WITH THE `OE_ENCLAVE_FLAG_DEBUG` ** because it is insecure. What it gives is the ability to develop your enclave more easily. Before you ship the code, you need to have a proper code signing story for the enclave executable. Some newer Intel SGX platforms allow self-signed certificates to be used, but some of the older Intel SGX platforms require Intel to sign your enclave executable.

On a successful creation, the function returns an opaque enclave handle for any future operation on the enclave.

> You can create multiple enclave instances this way if there are remaining enclave resources available, such as the Enclave Page Cache (EPC).

```c
result = enclave_helloworld(enclave);
if (result != OE_OK)
{
    fprintf(stderr, "calling into enclave_helloworld failed: result=%u (%s)\n", result, oe_result_str(result));
    goto exit;
}
```

This function calls into the host marshaling function that is generated from the `helloworld.edl` file. It handles the code that marshals any parameters, and calls the function within the enclave itself. In this sample, we do not have any actual function parameters. Even though the function `enclave_helloworld()` is a `void` return type, the marshaling code itself can fail, so we need to validate the return code associated with it. If `enclave_helloworld()` were to return a value, this would be passed back as an out parameter.

The Open Enclave handles all the context switching between the host mode and the enclave mode.

```c
oe_terminate_enclave
```

Terminates the enclave and frees up all resources associated with it.

### Build a host

The helloworld sample comes with a Makefile with a `build` target. You can run `make build` to generate the marshaling files and build the host app.

Listing of [helloworld/host/Makefile](host/Makefile)

```make
# Detect C and C++ compiler options
# if not gcc, default to clang-7

COMPILER=$(notdir $(CC))
ifeq ($(COMPILER), gcc)
        USE_GCC = true
endif

ifeq ($(USE_GCC),)
        CC = clang-7
        COMPILER=clang
endif

CFLAGS=$(shell pkg-config oehost-$(COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oehost-$(COMPILER) --libs)

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../helloworld.edl --untrusted
	$(CC) -c $(CFLAGS) host.c
	$(CC) -c $(CFLAGS) helloworld_u.c
	$(CC) -o helloworldhost helloworld_u.o host.o $(LDFLAGS)

clean:
	rm -f helloworldhost host.o helloworld_u.o helloworld_u.c helloworld_u.h helloworld_args.h

```

The following host files come with the sample:

| File | Description |
| --- | --- |
| host.c | Source code for the host `host_helloworld` function, as well as the executable `main` function. |
| Makefile | Makefile used to build the host |

The following files are generated during the build.

| File | Description |
| --- | --- |
| host.o | Compiled host.c source file |
| helloworldhost | built and linked host executable |
| helloworld_args.h | Defines the parameters that are passed to all functions defined in the edl file |
| helloworld_u.c | Contains the `enclave_helloworld()` function with the marshaling code to call into the enclave version of the `enclave_helloworld()` function |
| helloworld_u.h | Function prototype for `enclave_helloworld()` function |
| helloworld_u.o | compiled helloworld_u.c source file |


## Build and run

Open Enclave SDK supports building the sample on both Linux and Windows.
Linux supports two types of build systems, GNU Make with `pkg-config` and CMake,
while Windows supports only CMake.

### Linux

#### CMake

This uses the CMake package provided by the Open Enclave SDK.

```bash
cd helloworld
mkdir build && cd build
cmake ..
make run
```

#### GNU Make

```bash
cd helloworld
make build
make run
```

### Windows

#### CMake

```bash
mkdir build && cd build
cmake .. -G Ninja -DNUGET_PACKAGE_PATH=C:\oe_prereqs
ninja
ninja run
```

## Build and run with LVI mitigation

Starting from version `0.8.2`, the Open Enclave SDK supports mitigation against the LVI vulnerability.
With this support, you can build the sample with LVI mitigation, which ensures:
- All the enclave code is compiled with the mitigation.
- All the enclave code is linked against the mitigated version of Open Enclave libraries.

### Linux

#### Prerequisites

Use the `install_lvi_mitigation_bindir` script in the installation package to install the
dependencies the LVI mitigation.

The following example shows how to use the script (assume the package resides in `/opt/openenclave`).

```bash
~/openenclave/share/openenclave/samples$ /opt/openenclave/bin/scripts/lvi-mitigation/install_lvi_mitigation_bindir
Do you want to install in current directory? [yes/no]: yes
...
Installed: /home/yourname/openenclave/share/openenclave/samples/lvi_mitigation_bin
```

The directory `/home/yourname/openenclave/share/openenclave/samples/lvi_mitigation_bin` should contain all
the dependencies.

#### CMake

```bash
mkdir build
cd build
cmake -DLVI_MITIGATION=ControlFlow -DLVI_MITIGATION_BINDIR=/home/yourname/openenclave/share/openenclave/samples/lvi_mitigation_bin ..
make
make run
```

#### GNU Make

```bash
make LVI_MITIGATION=ControlFlow \
LVI_MITIGATION_BINDIR=/home/yourname/openenclave/share/openenclave/samples/lvi_mitigation_bin \
build
make run
```

### Windows

#### CMake

```bash
mkdir build && cd build
cmake .. -G Ninja -DNUGET_PACKAGE_PATH=C:\oe_prereqs -DLVI_MITIGATION=ControlFlow
ninja
ninja run
```

#### Note

helloworld sample can run under OE simulation mode.

To run the helloworld sample in simulation mode from the command like, use the following:

```bash
./host/helloworldhost ./enclave/helloworldenc.signed --simulate
```

## Next steps

In this tutorial, you built and ran the helloword sample. Next, try out more OE SDK samples on [Linux](https://github.com/JBCook/openenclave/blob/master/samples/README_Linux.md#samples) and [Windows](https://github.com/JBCook/openenclave/blob/master/samples/README_Windows.md#samples).
