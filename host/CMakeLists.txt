# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# OS specific but arch agnostic files.
if (UNIX)
    set(PLATFORM_SRC
        ../common/asn1.c
        ../common/cert.c
        crypto/openssl/asn1.c
        crypto/openssl/cert.c
        crypto/openssl/crl.c
        crypto/openssl/ec.c
        crypto/openssl/hmac.c
        crypto/openssl/init.c
        crypto/openssl/key.c
        crypto/openssl/random.c
        crypto/openssl/rsa.c
        linux/hostthread.c
        linux/time.c
        linux/windows.c
    )
elseif (WIN32)
    set(PLATFORM_SRC
        ../3rdparty/mbedtls/mbedtls/library/bignum.c
        crypto/bcrypt/hmac.c
        crypto/bcrypt/rsa.c
        windows/hostthread.c
        windows/time.c
    )
else()
    message(FATAL_ERROR "Unknown OS. Only supported OSes are Linux and Windows")
endif()

# Arch specific files. Right now, don't distinguish Intel vs AMD.
if (CMAKE_SYSTEM_PROCESSOR MATCHES "amd64.*|x86_64.*|AMD64.*")
    list(APPEND PLATFORM_SRC
        ../common/sgx/qeidentity.c
        ../common/sgx/quote.c
        ../common/sgx/report.c
        ../common/sgx/revocation.c
        ../common/sgx/sgxcertextensions.c
        ../common/sgx/tcbinfo.c    
        sgx/calls.c
        sgx/create.c 
        sgx/elf.c
        sgx/enclave.c
        sgx/enclavemanager.c
        sgx/load.c
        sgx/loadelf.c
        sgx/loadpe.c
        sgx/ocalls.c
        sgx/quote.c
        sgx/registers.c
        sgx/report.c
        sgx/sgxload.c
        sgx/sgxmeasure.c
        sgx/sgxquote.c
        sgx/sgxquoteprovider.c
        sgx/sgxsign.c
        sgx/sgxtypes.c
    )

    # OS specific as well.
    if (UNIX)
        list(APPEND PLATFORM_SRC
            sgx/linux/aep.S
            sgx/linux/aesm.c
            sgx/linux/cpuid.c
            sgx/linux/enter.S
            sgx/linux/entersim.S
            sgx/linux/exception.c
            sgx/linux/sgxioctl.c
        )
    else()
        list(APPEND PLATFORM_SRC
            sgx/windows/aep.asm
            sgx/windows/aesm.c
            sgx/windows/cpuid.c
            sgx/windows/enter.asm
            sgx/windows/entersim.asm
            sgx/windows/exception.c
        )
    endif()
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm.*|ARM.*|aarch64.*|AARCH64.*")
    message("TODO: ADD ARM files.")
else()
    message(FATAL_ERROR "Unknown architecture. Only Intel and ARM are supported.")
endif()    

# Combine with all other non platform dependent files.
add_library(oehost STATIC
    ../common/datetime.c
    ../common/kdf.c
    ../common/safecrt.c
    dupenv.c
    error.c
    exception.c
    files.c
    fopen.c
    hexdump.c
    memalign.c
    ocalls.c
    traceh.c
    result.c
    signkey.c
    strings.c
    tests.c
    crypto/sha.c
    ${PLATFORM_SRC}
    )

# we and dependents need the OE includes to compile
target_link_libraries(oehost PUBLIC oe_includes)

target_compile_definitions(oehost PRIVATE -DOE_REPO_BRANCH_NAME="${GIT_BRANCH}" -DOE_REPO_LAST_COMMIT="${GIT_COMMIT}")

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
target_compile_options(oehost PRIVATE -Wno-attributes -Wmissing-prototypes -fPIC -m64)
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
