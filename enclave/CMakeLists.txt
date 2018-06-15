# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_library(oeenclave STATIC
    cert.c
    ec.c
    ../common/quote.c
    cmac.c
    key.c
    random.c
    report.c
    rsa.c
    sha.c)

if(USE_LIBSGX)
target_compile_definitions(oeenclave PUBLIC OE_USE_LIBSGX)
endif()    

# Linker can optimize out liboeenclave if no symbol from liboeenclave is used
# by the enclave. Adding --undefined=__liboeenclave ensure that liboeenclave
# is not optimized out. __liboeenclave is just a function. Host side
# oe_verify_report relies on oe_verify_report being present in the enclave.

target_link_libraries(oeenclave PUBLIC
    -Wl,--undefined=__liboeenclave
    mbedcrypto
    oelibc)

set_property(TARGET oeenclave PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/enclave)

install(TARGETS oeenclave ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
