# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_library(oeenclave STATIC
    cert.c
    ec.c
    ../common/quote.c
    cmac.c
    init.c
    key.c
    random.c
    report.c
    rsa.c
    sha.c)

if(USE_LIBSGX)
target_compile_definitions(oeenclave PUBLIC OE_USE_LIBSGX)
endif()    

# Enclave applications that link liboenclave must specify the -Wl option
# as shown below so that liboecore calls the strong version of 
# __liboeenclave_init() (defined in liboeenclave) rather than the weak 
# version (defined in liboecore). This public definition propagates this
# linker option to cmake scripts that reference the 'oeenclave' target.
target_link_libraries(oeenclave PUBLIC
    -Wl,--require-defined=__liboeenclave_init
    mbedcrypto
    oelibc)

set_property(TARGET oeenclave PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/enclave)

install(TARGETS oeenclave ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
