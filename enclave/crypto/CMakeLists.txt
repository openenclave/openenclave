# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_library(oecrypto STATIC
    ../../common/asn1.c
    asn1.c
    cert.c
    crl.c
    ec.c
    cmac.c
    hmac.c
    key.c
    random.c
    rsa.c
    sha.c)

maybe_build_using_clangw(oecrypto)

target_include_directories(oecrypto PRIVATE
    ${PROJECT_SOURCE_DIR}/include/openenclave/corelibc)

target_link_libraries(oecrypto PUBLIC
    oe_includes
    mbedcrypto)

set_property(TARGET oecrypto PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/enclave)

install(TARGETS oecrypto EXPORT openenclave-targets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
