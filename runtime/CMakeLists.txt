# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_library(oeruntime STATIC 
    cert.c
    ec.c
    rsa.c
    random.c
    sha.c)

target_link_libraries(oeruntime PUBLIC 
    mbedcrypto
    oelibc)

set_property(TARGET oeruntime PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/enclave)

install(TARGETS oeruntime ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
