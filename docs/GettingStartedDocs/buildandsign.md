# Build and Sign an Enclave

## Build options for using Open Enclave SDK libraries

As with the Intel SGX SDK, Open Enclave SDK currently only supports building single-binary enclaves.
Also like the Intel SGX SDK, these binaries must be built with a specific set of includes and build flags.

To simplify the process of the specifying the correct build parameters, Open Enclave SDK provides
a set of `pkg-config` settings that you can use in your build scripts.

There are 8 configurations provided to handle all permutations of the following parameters:
* Building enclave or host binary
* Using GCC or Clang build tools
* Compiling C or C++ code

The provided configurations use the following naming syntax:

```
oe<enclave|host>-<gcc|g++|clang|clang++>
```

For example, if you have added the Open Enclave SDK `pkgconfig` to your `PKG_CONFIG_PATH`,
you can specify in your Makefile how to build your C enclave using Clang-7:

```make
CFLAGS=$(shell pkg-config oeenclave-clang --cflags)
LDFLAGS=$(shell pkg-config oeenclave-clang --libs)

$(CC) -c $(CFLAGS) my_enclave.c -o my_enclave.o
$(CC) -o my_enclave my_enclave.o $(LDFLAGS)
```

You can also display in the shell what the options are with by runnin `pkg-config`
directly. For example, to see the host linker options when building C++ code with GCC:

```bash
pkg-config opt/openenclave/share/pkgconfig/oehost-g++.pc --libs
```

## Signing the Enclave

Before the enclave can be run, the properties that define how the enclave should
be loaded need to be specified for the enclave. These properties, along with the
signing key, define the enclave identity that is used for attestation and sealing
operations.

In the Open Enclave SDK, these properties can be attached to the enclave as part
of the signing process. To do so, you will need to use the oesign tool, which
takes the following parameters:

```bash
Usage: oesign ENCLAVE CONFFILE KEYFILE
```

For example, to sign the helloworld sample enclave in the output folder:
```bash
/opt/openenclave/bin/oesign helloworld_enc enc.conf private.pem
```

**When signing the enclave, the `KEYFILE` specified must contain a 3072-bit RSA keys
with exponent 3.**

To generate your own private keypair yourself, you can install the OpenSSL package and run:

```bash
openssl genrsa -out myprivate.pem -3 3072
```

The `CONFFILE` is a simple text file that defines enclave settings.
All the settings must be provided for the enclave to be successfully loaded:

- **Debug**: Is the enclave allowed to load in debug mode? 
- **NumTCS**: The number of thread control structures (TCS) to allocate in the enclave.
  This determines the maximum number of concurrent threads that can be executing in the enclave.
- **NumStackPages**: The number of stack pages to allocate for each thread in the enclave.
- **NumHeapPages**: The number of pages to allocate for the enclave to use as heap memory.

All these properties will also be reflected in the UniqueID (MRENCLAVE) of the resulting enclave.
In addition, the following two properties are defined by the developer and map directly to the following SGX identity properties:

- **ProductID**: The product identity (ISVPRODID) for the developer to distinguish
  between different enclaves signed with the same MRSIGNER value.
- **SecurityVersion**: The security version number for the enclave (ISVSVN), which 
  can be used to prevent rollback attacks against sealing keys. This value should be
  incremented whenever a security fix is made to the enclave code.

Here is the example from helloworld.conf used in the helloworld sample:
```
# Enclave settings:
Debug=1
NumHeapPages=1024
NumStackPages=1024
NumTCS=1
ProductID=1
SecurityVersion=1
```

As a convenience, you can also specify the enclave properties in code using the
`OE_SET_ENCLAVE_SGX` macro. For example, the equivalent properties could be
defined in any .cpp compiled into the enclave: 

```c
OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    1);   /* TCSCount */
```

Specifying the enclave properties using the `OE_SET_ENCLAVE_SGX` also allows you
to run an enclave in debug mode without signing it first. In this case, the enclave
is treated as having the standard signer ID (MRSIGNER) value of:

> CA9AD7331448980AA28890CE73E433638377F179AB4456B2FE237193193A8D0A

Any properties set in the code also serve as default values when the enclave is
signed using oesign, so the signing `CONFFILE` only needs to specify override
parameters during signing.

**Since enclaves that run in debug mode are not confidential, you should disable
the ability to run the enclave in debug mode before deploying it into production.**

For example, to toggle an enclave to disable debug mode when signed, you could
specify a `CONFFILE` that only changed that property:

```
# Enclave settings:
Debug=0
```
