# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_library(oecryptohost STATIC
    cert.c
    ec.c
    init.c
    random.c
    rsa.c
    ../util.c)

target_link_libraries(oecryptohost oe_includes)

find_package(Threads REQUIRED)

target_link_libraries(oecryptohost)

if(UNIX)
    target_compile_options(oecryptohost PRIVATE 
        -Wno-attributes 
        -Wmissing-prototypes 
        -m64)
    target_compile_definitions(oecryptohost PRIVATE _GNU_SOURCE)
endif(UNIX)

set_property(TARGET oecryptohost PROPERTY ARCHIVE_OUTPUT_DIRECTORY 
    ${OE_LIBDIR}/openenclave/host)

install(TARGETS oecryptohost 
    EXPORT 
    openenclave 
    ARCHIVE 
    DESTINATION 
    ${CMAKE_INSTALL_LIBDIR}/openenclave/host)

