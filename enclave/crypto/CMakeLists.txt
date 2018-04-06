# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_library(oecrypto STATIC 
    cert.c
    ec.c
    rsa.c
    random.c
    sha.c)

target_link_libraries(oecrypto PUBLIC 
    mbedcrypto
    oelibc
    oe_includes)

set_property(TARGET oecrypto PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/enclave)

install(TARGETS oecrypto ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
