# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

if (UNIX)
set(PLATFORM_SRC
    ../common/asn1.c
    ../common/cert.c
    crypto/openssl/asn1.c
    crypto/openssl/cert.c
    crypto/openssl/crl.c
    crypto/openssl/ec.c
    crypto/openssl/init.c
    crypto/openssl/key.c
    crypto/openssl/random.c
    crypto/openssl/rsa.c
    linux/aep.S
    linux/aesm.c
    linux/cpuid.c
    linux/enter.S
    linux/entersim.S
    linux/exception.c
    linux/hostthread.c
    linux/sgxioctl.c
    linux/time.c
    linux/windows.c
    sgxquoteprovider.c
    )
elseif (WIN32)
set(PLATFORM_SRC
    crypto/bcrypt/rsa.c
    windows/aep.asm
    windows/aesm.c
    windows/cpuid.c
    windows/enter.asm
    windows/entersim.asm
    windows/exception.c
    windows/hostthread.c
    windows/time.c
    ../3rdparty/mbedtls/mbedtls/library/bignum.c
    )
endif()

add_library(oehost STATIC
    ../common/datetime.c
    ../common/qeidentity.c
    ../common/quote.c
    ../common/report.c
    ../common/revocation.c
    ../common/safecrt.c
    ../common/sgxcertextensions.c
    ../common/tcbinfo.c    
    calls.c
    create.c
    dupenv.c
    elf.c
    enclave.c
    enclavemanager.c
    error.c
    files.c
    fopen.c
    hexdump.c
    load.c
    loadelf.c
    loadpe.c
    memalign.c
    ocalls.c
    quote.c
    registers.c
    report.c
    result.c
    sgxload.c
    sgxmeasure.c
    sgxquote.c
    sgxsign.c
    sgxtypes.c
    signkey.c
    strings.c
    tests.c
    crypto/sha.c
    ${PLATFORM_SRC}
    )

# we and dependents need the OE includes to compile
target_link_libraries(oehost PUBLIC oe_includes)

if(UNIX)
find_library(CRYPTO_LIB NAMES crypto)
find_library(DL_LIB NAMES dl)
endif(UNIX)
find_package(Threads REQUIRED)

# linking also requires a number of libs on the host
if(UNIX)
target_link_libraries(oehost PRIVATE ${CRYPTO_LIB} ${DL_LIB} Threads::Threads)
elseif(WIN32)
target_include_directories(oehost PRIVATE ${CMAKE_SOURCE_DIR}/3rdparty/mbedtls/mbedtls/include)
target_link_libraries(oehost PRIVATE bcrypt Crypt32)
endif()

if(UNIX)
target_compile_options(oehost PRIVATE -Wno-attributes -Wmissing-prototypes -Wconversion -Wpointer-arith -fPIC -m64)
target_compile_definitions(oehost PRIVATE _GNU_SOURCE)
endif(UNIX)

if(CMAKE_C_COMPILER_ID MATCHES GNU)
target_compile_options(oehost PRIVATE -Wjump-misses-init)
endif()

target_compile_definitions(oehost PRIVATE OE_BUILD_UNTRUSTED)

# Additional compilation and link options when using libsgx
if(USE_LIBSGX)
message("USE_LIBSGX is set, building oehost with FLC dependency")
find_library(LIBSGX_COMMON NAMES sgx_enclave_common)
find_library(LIBSGX_QE NAMES sgx_dcap_ql)
find_library(LIBSGX_URTS NAMES sgx_urts)
target_link_libraries(oehost PUBLIC ${LIBSGX_COMMON} ${LIBSGX_QE} ${LIBSGX_URTS})
endif()

if(OE_TRACE_LEVEL)
    target_compile_definitions(oehost PUBLIC "OE_TRACE_LEVEL=${OE_TRACE_LEVEL}")
endif()

if(USE_DEBUG_MALLOC)
target_compile_definitions(oehost PRIVATE OE_USE_DEBUG_MALLOC)
endif()

if(USE_LIBSGX)
    target_compile_definitions(oehost PUBLIC OE_USE_LIBSGX)
endif()

# convenience library for creating a host-app (that needs the -rdynamic link flag)
add_library(oehostapp INTERFACE)
if(UNIX)
target_link_libraries(oehostapp INTERFACE oehost -rdynamic)
elseif(WIN32)
target_link_libraries(oehostapp INTERFACE oehost)
endif()

# assemble lib-archive into proper dir
set_property(TARGET oehost PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/host)

# install lib-archive upon install-time
install(TARGETS oehost EXPORT openenclave-targets ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/host)

# provide oehostapp to install-base as well
install(TARGETS oehostapp EXPORT openenclave-targets)
