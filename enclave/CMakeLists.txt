# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_library(oeenclave STATIC
    asn1.c
    cert.c
    crl.c
    ec.c
    ../../common/cert.c
    ../../common/outbuf.c    
    ../common/json.c
    ../common/quote.c
    ../common/revocation.c
    ../common/sgxcertextensions.c    
    ../common/tcbinfo.c
    cmac.c
    key.c
    random.c
    report.cpp
    rsa.c
    sha.c)

if(USE_LIBSGX)
target_compile_definitions(oeenclave PUBLIC OE_USE_LIBSGX)
endif()    

target_link_libraries(oeenclave PUBLIC
    mbedcrypto
    oelibc)

set_property(TARGET oeenclave PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/enclave)

install(TARGETS oeenclave ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
