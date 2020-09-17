# Intel SGX SDK to Open Enclave SDK Porting Guide (Linux)

Intel SGX SDK and Open Enclave SDK share many design principles but differ in
implementations. It requires source code changes to build enclaves with Open
Enclave SDK that were developed initially with Intel SGX SDK.

Please note that this doc focuses on **Linux**, and applies to *Intel SGX SDK
for Linux* only unless explicitly noted otherwise.

## Create Project Build Files

Open Enclave SDK supports a number of build systems, among which `cmake` is a
convenient one. This section shows how to build an enclave using `cmake`. For
those not familiar with `cmake`, a tutorial is available at
https://cmake.org/cmake/help/latest/guide/tutorial/index.html.

Firstly, a `CMakeLists.txt` file needs to be created in the enclave's source
directory. Open Enclave requires `cmake 3.11` or later so the first statement
should be:

```cmake
cmake_minimum_required(VERSION 3.11)
```

Then an enclave is just a C/C++ project.

```cmake
project("MyEnclaveProject" LANGUAGE C CXX)
```

Next, import the `OpenEnclave` package. Please note that the statement below
requires appending */path/to/OpenEnclave_InstallDir* to `CMAKE_PREFIX_PATH`
environment variable, or appending */path/to/OpenEnclave_InstallDir*/bin to
`PATH`. A convenient way to do it is to source
*/path/to/OpenEnclave_InstallDir*/shared/openenclave/openenclaverc.

```cmake
find_package(OpenEnclave CONFIG REQUIRED)
```

Now generate the ECall/OCall bridge/proxy routines for the enclave.

```cmake
add_custom_command(
  OUTPUT MyEnclave_t.h MyEnclave_t.c MyEnclave_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/MyEnclave.edl
  COMMAND openenclave::oeedger8r --trusted ${CMAKE_SOURCE_DIR}/MyEnclave.edl
          --search-path ${OE_INCLUDEDIR})
```

Finally, build the enclave as an executable. Please don't forget to include
`MyEnclave_t.c` (generated above) in the source list.

```cmake
add_executable(MyEnclave MyEnclave.cpp ${CMAKE_CURRENT_BINARY_DIR}/MyEnclave_t.c)

# Current API version
target_compile_definitions(MyEnclave PUBLIC OE_API_VERSION=2)

# Needed by the generated MyEnclave_t.c
target_include_directories(MyEnclave PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(MyEnclave openenclave::oeenclave openenclave::oelibc)
```

Enclaves must be signed before they can be loaded. How to sign an enclave
depends on how the signing private key is managed in your project. For
demonstration purposes, the following snippet generates a random RSA key pair
to sign the enclave. An enclave configuration file (`MyEnclave.conf` below) may
also be provided. Details of enclave configuration/settings are described later
in this document.

```cmake
# Generate key
add_custom_command(
  OUTPUT private.pem public.pem
  COMMAND openssl genrsa -out private.pem -3 3072
  COMMAND openssl rsa -in private.pem -pubout -out public.pem)

# Sign enclave
add_custom_command(
  OUTPUT MyEnclave.signed
  DEPENDS MyEnclave MyEnclave.conf private.pem
  COMMAND openenclave::oesign sign -e $<TARGET_FILE:MyEnclave>
          -c ${CMAKE_SOURCE_DIR}/MyEnclave.conf -k private.pem)
```

Readers are encouraged to look for complete examples under
*/path/to/OpenEnclave_InstallDir*/share/openenclave/samples directory.

## Migrate Enclave Settings

**Enclave Settings**, also known as **Enclave Metadata**, refers to information
consumed by enclave loaders to instantiate enclaves, such as heap size, stack
size, number of trusted hardware threads (i.e., number of TCS's), etc.

Enclave settings are specified in human readable text formats by enclave
developers, referred to as *configuration files*. Both Intel SGX SDK and Open
Enclave SDK provide tools to compile configuration files into their binary form
and embed them into the final enclave image. However, they differ in both
format and feature set.

### Configuration File Formats

The Intel SGX SDK adopted an XML format for encoding enclave settings in text
form, which is usually named as *Enclave*.config.xml. The signing tool (i.e.,
`sgx_sign`) converts it into binary form and stores it in a dedicated section
(i.e., `.sgxmeta`) of the enclave's ELF image before it calculates the
enclave's measurement (i.e., `SIGSTRUCT::MRENCLAVE`). At runtime, the ELF
section `.sgxmeta` is consumed by the enclave loader to instantiate the exact
enclave that matches the measurement calculated by the signing tool.

Below comes from the sample code - SampleEnclave, of Intel SGX SDK.

```xml
<EnclaveConfiguration>
  <ProdID>0</ProdID>
  <ISVSVN>0</ISVSVN>
  <StackMaxSize>0x40000</StackMaxSize>
  <HeapMaxSize>0x100000</HeapMaxSize>
  <TCSNum>10</TCSNum>
  <TCSPolicy>1</TCSPolicy>
  <!-- Recommend changing 'DisableDebug' to 1 to make the enclave undebuggable for enclave release -->
  <DisableDebug>0</DisableDebug>
  <MiscSelect>0</MiscSelect>
  <MiscMask>0xFFFFFFFF</MiscMask>
</EnclaveConfiguration>
```

Rather than XML, Open Enclave SDK uses plaintext files instead. A configuration
file, usually named *enclave*.conf, is supplied to the signing tool (i.e.,
`oesign`) command line to govern the instantiation of the enclave. The compiled
metadata is then stored in a dedicated ELF section named `.oeinfo`.
Additionally, Open Enclave SDK provides `OE_SET_ENCLAVE_SGX`, a C macro for
embedding default enclave settings in C source files. *enclave*.conf is in fact
optional and is necessary only if some of those defaults provided to
`OE_SET_ENCLAVE_SGX` macro need overridden. Under the hood,
`OE_SET_ENCLAVE_SGX` is expanded to instantiation of an
`oe_sgx_enclave_properties_t` structure in `.oeinfo` section. Detailed
information can be found in
[buildandsign.md](https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/buildandsign.md)
in Open Enclave SDK documentation.

Below is the same configuration as above but in Open Enclave SDK's
*enclave*.conf format.

```
# <ProdID>0</ProdID>
ProductID=0

# <ISVSVN>0</ISVSVN>
SecurityVersion=0

# <StackMaxSize>0x40000</StackMaxSize>
NumStackPages=64

# <HeapMaxSize>0x100000</HeapMaxSize>
NumHeapPages=256

# <TCSNum>10</TCSNum>
NumTCS=10

# <DisableDebug>0</DisableDebug>
Debug=1

# There are no equivalent Open Enclave enclave settings for the following
# <TCSPolicy>1</TCSPolicy>
# <MiscSelect>0</MiscSelect>
# <MiscMask>0xFFFFFFFF</MiscMask>
```

### Supported Enclave Settings by Intel SGX and Open Enclave SDKs

At the time of this writing, Intel SGX SDK supports a superset of Open Enclave
SDK's features, hence not every element of Intel SGX SDK's *Enclave*.conf.xml
has a corresponding setting in Open Enclave SDK's *enclave*.conf file. The
table below summarizes the correspondence and difference.

|.xml Element (Intel)|.conf Key (Open Enclave)|Type|Definition|Notes|
|---|---|---|---|---|
|`<ProdID>`|`ProductID`|`uint16_t`|`SIGSTRUCT::ISVPRODID` - 2-byte product ID chosen by ISV
|`<ISVSVN>`|`SecurityVersion`|`uint16_t`|`SIGSTRUCT::ISVSVN` - 2-byte security version number to prevent rollback attacks against sealing keys
|`<ReleaseType>`||`bool`|`1` indicates a release build|Intel SDK copies this bit to MSB of `SIGSTRUCT::HEADER`. Open Enclave does *NOT* support configuring this bit but hard-codes it to `0`.This bit is *NOT* documented in [SDM](https://software.intel.com/content/www/us/en/develop/articles/intel-sdm.html). User enclaves shall avoid using this bit.
|`<IntelSigned>`||`bool`|If `1`, set `SIGSTRUCT::VENDOR` to `0x8086` (or `0` otherwise)|Open Enclave does *NOT* support configuring this field currently but hard-codes it to `0`. Per SDM, this field is informational.
|`<ProvisionKey>`||`bool`|`1` to grant access to *Provision Key*. This corresponds to bit 4 of `SIGSTRUCT::ATTRIBUTES`|`Debug` is the only attribute configurable via Open Enclave's .conf file. All other attributes can only be configured by enclosing an `oe_sgx_enclave_properties_t` structure manually in the `.oeinfo` section in a source file.|`<LaunchKey>`||`bool`|`1` to grant access to *Launch Key*. This corresponds to bit 5 of `SIGSTRUCT::ATTRIBUTES`|Similar to `<ProvisionKey>` above, manual instantiation of `oe_sgx_enclave_properties_t` is required.
|`<DisableDebug>`|`Debug`|`bool`|Indicate whether debugging is allowed|Intel and Open Enclave SDKs use different polarity - i.e. `<DisableDebug>1</DisableDebug>` is equivlanet to `Debug=0`.
|`<HW>`||`uint32_t`|Hardware verions. This occupies the space of `SIGSTRUCT::SWDEFINED`|Currently it's used only by Intel's LE (Launch Enclave). Open Enclave does *NOT* support configuring this field currently but hard-codes it to `0`. User enclaves shall avoid using it.
|`<TCSNum>`|`NumTCS`|`uint32_t`|Number of TCS's (trusted threads)|This is the number of TCS's, and is also the initial number of TCS's on SGX v2. Open Enclave supports only SGX v1 at the moment.
|`<TCSMaxNum>`||`uint32_t`|Maximal number of TCS's|TCS's can be added at runtime on SGX v2. Open Enclave supports only SGX v1 at the moment.
|`<TCSMinPool>`||`uint32_t`|Minimal number of TCS's to keep|TCS's can be removed at runtime on SGX v2. Open Enclave supports only SGX v1 at the moment.
|`<TCSPolicy>`||`bool`|`0` to bind TCS to untrusted thread, `1` to unbind them|Open Enclave SDK never does not bind TCS's to untrusted threads.
|`<StackMaxSize>`|`NumStackPages`|`uint64_t`|Maximal stack size in bytes (Intel) or in pages (Open Enclave)|This is the stack size on SGX v1, or maximal stack size on SGX v2. Open Enclave supports only SGX v1 at the moment.
|`<StackMinSize>`||`uint64_t`|Minimal stack size in bytes|Stack pages can be removed at runtime on SGX v2. Open Enclave supports only SGX v1 at the moment.
|`<HeapMaxSize>`||`uint64_t`|Maximal heap size in bytes|For SGX v2 only. Open Enclave supports only SGX v1 at the moment.
|`<HeapMinSize>`||`uint64_t`|Minimal heap size in bytes|For SGX v2 only. Open Enclave supports only SGX v1 at the moment.
|`<HeapInitSize>`|`NumHeapPages`|`uint64_t`|Initial heap size in bytes (Intel) or pages (Open Enclave)|Open Enclave supports only SGX v1 at the moment.
|`<ReservedMemMaxSize>`||`uint64_t`||This, along with the `ReservedMem*` elements below, allows appending extra virtual memory to an enclave. Open Enclave doesn't support this feature.
|`<ReservedMemMinSize>`||`uint64_t`
|`<ReservedMemInitSize>`||`uint64_t`
|`<ReservedMemExecutable>`||`uint64_t`
|`<MiscSelect>`||`uint32_t`|`SIGSTRUCT::MISCSELECT` - selects extended information to be reported on AEX|Open Enclave does *NOT* support configuring this field currently but hard-codes it to `0` (i.e. no MISC features are enabled).
|`<MiscMask>`||`uint32_t`|`SIGSTRUCT::MISCMASK` - selects `MISCSELECT` bits to enforce|Open Enclave does *NOT* support configuring this field currently but hard-codes it to `0xffffffff` (i.e. all bits are enforced).
|`<EnableKSS>`||`bool`|`1` to enable *Key Separation and Sharing*|Open Enclave supports only SGX v1 at the moment.
|`<ISVFAMILYID_H>`||`uint64_t`|This, along with `<ISVFAMILYID_L>` below, forms 16-byte `SIGSTRUCT::ISVFAMILYID`|Open Enclave supports only SGX v1 at the moment.
|`<ISVFAMILYID_L>`||`uint64_t`|See above|
|`<ISVEXTPRODID_H>`||`uint64_t`|This, along with `<ISVEXTPRODID_L>` below, forms 16-byte `SIGSTRUCT::ISVEXTPRODID`|Open Enclave supports only SGX v1 at the moment.
|`<ISVEXTPRODID_L>`||`uint64_t`|See above|

As mentioned in the *Notes* column above, certain missing feature, such as
those controlling SGX enclave attribute bits (e.g., `<LaunchKey>`,
`<ProvisionKey>`), could still be enabled by setting
`oe_sgx_enclave_properties_t::config.attributes` manually, even though they
aren't supported explicitly by the `OE_SET_ENCLAVE_SGX` macro or *enclave*.conf
file. Below is an example that grants the enclave access to `PROVISION_KEY`.

```C
OE_INFO_SECTION_BEGIN
volatile const oe_sgx_enclave_properties_t oe_enclave_properties_sgx = {
    .header = {.size = sizeof(oe_sgx_enclave_properties_t),
               .enclave_type = OE_ENCLAVE_TYPE_SGX,
               .size_settings = {.num_heap_pages = 512,
                                 .num_stack_pages = 512,
                                 .num_tcs = 4}},
    .config = {.product_id = 1234,
               .security_version = 5678,
               .attributes = OE_SGX_FLAGS_PROVISION_KEY |
                             OE_MAKE_ATTRIBUTES(0)},
    .end_marker = 0xecececececececec};
OE_INFO_SECTION_END
```

If compatibilities with both SDKs are desired, avoid using features specific to
either SDK.

As a final note, neither Intel SGX SDK nor Open Enclave SDK provides
configuration settings for enabling/disabling X features (e.g., AVX, AVX-512,
etc.) explicitly. Open Enclave's SGX enclave loader uses the enabled X features
on the local platform to initialize `SECS::ATTRIBUTES::XFRM`, and hard-codes
`SIGSTRUCT::ATTRIBUTEMASK::XFRM` to `0`. That is, X features are *NOT* enforced
and must *NOT* be relied upon for security.

## Migrate ECall/OCall Definitions (EDL Files)

Both Intel SGX SDK and Open Enclave SDK support the same grammer for defining
trusted/untrusted functions (aka. ECalls/OCalls) in EDL files. However,
built-in OCalls are defined in different headers. Intel SGX SDK's built-in
OCalls are defined in `sgx_tstdc.edl` while Open Enclave SDK's are defined in
`platform.edl`.

Most EDL files include (by `include` statements) common C headers for both host
and enclave sides. The most commonly included header is the one defining SGX
architectural structures, which is `arch.h` in Intel SGX SDK or
`openenclave/bits/sgx/sgxtypes.h` in Open Enclave SDK. Please also note that
some structures may be named differently, e.g., the EINITTOKEN architectural
structure is defined as `token_t` in Intel SGX SDK but `einittoken_t` in Open
Enclave SDK.

The code snippet below shows a way to include/import C headers and EDL
definitions conditionally, in order to be compatible with both Intel SGX and
Open Enclave SDKs.

```
enclave {
#ifdef OEEDGER8R
    include "openenclave/bits/sgx/sgxtypes.h";
    from "openenclave/edl/sgx/platform.edl" import *;
#else
    include "arch.h";
    from "sgx_tstdc.edl" import *;
#endif
    /* ECall/OCall definitions go here */
}
```

The macro `OEEDGER8R` used above could be defined by appending `-DOEEDGER8R` to
`oeedger8r` command line. Please note that only `oeedger8r` supports defining
macros at command line, even though both `sgx_edger8r` and `oeedger8r` support
preprocessing.

The last thing worth noting is that Open Enclave doesn't support nested ECall
(i.e., an ECall in the context of an OCall) like the Intel SGX SDK does.
Existing enclaves making use of nested ECalls need to be reworked to be
compatible with the Open Enclave SDK.

## Port C/C++ Source Code

Given similarities in the architectures of both SDKs, there shall not be any
significant code flow/logic changes required. However, source code
incompatibilities still exist in
- Header files - They are structured and/or named differently. Fortunately,
  Open Enclave provides 2 comprehensive headers, namely `openenclave/enclave.h`
  and `openenclave/host.h`, to be included by trusted and untrusted code,
  respectively. A single `#include` should suffice in most cases.
- APIs - Most Open Enclave APIs are prefixed by `oe_` while Intel's APIs are by
  `sgx_`. Moreover, some APIs may take parameters in different orders.
- Structure definitions - Structure members may be named differently. Some
  structures are organized differently. For example, Intel SGX SDK defines
  EINITTOKEN as `token_t` with all MAC'ed fields captured in a child structure
  `launch_body_t`; while Open Enclave defines it as a flat `einittoken_t`
  structure.
- Crypto lib - Intel SGX SDK supports 2 crypto libs - IPP and OpenSSL, and
  provides a wrapper layer to unify crypto APIs. Open Enclave supports only
  MbedTLS and provides no wrapper.

Generally, there's no good way to fast port source code rather than reacting to
compiler errors and substituting text strings manually.
