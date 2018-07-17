# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_library(oeenclave STATIC
    cert.c
    ec.c
    ../common/quote.c
    cmac.c
    key.c
    link.c
    random.c
    report.c
    rsa.c
    sha.c
    start.S)

if(USE_LIBSGX)
target_compile_definitions(oeenclave PUBLIC OE_USE_LIBSGX)
endif()    

target_link_libraries(oeenclave PUBLIC
    mbedcrypto
    oelibc)

set_property(TARGET oeenclave PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/enclave)

install(TARGETS oeenclave ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
