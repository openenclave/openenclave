# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

if (CMAKE_SYSTEM_PROCESSOR MATCHES "amd64.*|x86_64.*|AMD64.*")
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
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm.*|ARM.*|aarch64.*|AARCH64.*")
    message("TODO: ADD ARM files.")
else()
    message(FATAL_ERROR "Unknown architecture. Only Intel and ARM are supported.")
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

if(CMAKE_C_COMPILER_ID MATCHES GNU)
target_compile_options(oeenclave PRIVATE -Wjump-misses-init)
endif()

target_link_libraries(oeenclave PUBLIC
    mbedcrypto
    oelibc)

set_property(TARGET oeenclave PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/enclave)

install(TARGETS oeenclave EXPORT openenclave-targets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
