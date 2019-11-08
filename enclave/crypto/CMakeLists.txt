# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_library(oecryptombed STATIC
    ../../common/asn1.c
    ../../common/cert.c
    ../../common/kdf.c
    asn1.c
    cert.c
    crl.c
    ec.c
    cmac.c
    hmac.c
    key.c
    random_internal.c
    rsa.c
    sha.c)

maybe_build_using_clangw(oecryptombed)

target_link_libraries(oecryptombed PUBLIC mbedcrypto)

set_property(TARGET oecryptombed PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/enclave)

install(TARGETS oecryptombed EXPORT openenclave-targets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
