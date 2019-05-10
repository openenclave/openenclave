# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

if (OE_SGX)
    set(PLATFORM_SRC
        ../common/sgx/qeidentity.c
        ../common/sgx/quote.c
        ../common/sgx/report.c
        ../common/sgx/revocation.c
        ../common/sgx/sgxcertextensions.c
        ../common/sgx/tcbinfo.c
        sgx/link.c
        sgx/qeidinfo.c
        sgx/report.c
        sgx/revocationinfo.c
        sgx/start.S
    )
elseif(OE_TRUSTZONE)
    message("TODO: ADD ARM files.")
endif()

add_library(oeenclave STATIC
    ../common/asn1.c
    ../common/cert.c
    ../common/datetime.c
    ../common/kdf.c
    asn1.c
    asym_keys.c
    cert.c
    crl.c
    ec.c
    cmac.c
    hmac.c
    key.c
    random.c
    rsa.c
    sha.c
    ${PLATFORM_SRC})

maybe_build_using_clangw(oeenclave)

if(CMAKE_C_COMPILER_ID MATCHES GNU)
target_compile_options(oeenclave PRIVATE -Wjump-misses-init)
endif()

target_include_directories(oeenclave PRIVATE
    ${PROJECT_SOURCE_DIR}/include/openenclave/corelibc)

target_link_libraries(oeenclave PUBLIC
    oe_includes
    mbedcrypto)

set_property(TARGET oeenclave PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/enclave)

install(TARGETS oeenclave EXPORT openenclave-targets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)

if (OE_SGX)
add_subdirectory(start)
endif()
