# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_library(oecrypto STATIC
    oe_cert.c
    oe_cmac.c
    oe_ec.c
    oe_key.c
    oe_random.c
    oe_rsa.c
    oe_sha.c)

target_link_libraries(oecrypto PRIVATE
    mbedcrypto
    oelibc)

set_property(TARGET oecrypto 
    PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/enclave)

set(ENCLAVE_LIBDIR "${OE_LIBDIR}/openenclave/enclave")

install(TARGETS oecrypto 
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)

target_include_directories(oecrypto INTERFACE ${OE_INCDIR}/openenclave)

# Merge the the MBEDTLS libraries into oecrypto.
add_custom_command(TARGET oecrypto
    COMMAND sh -c "rm -rf *.o"
    COMMAND sh -c "ar xs ${ENCLAVE_LIBDIR}/libmbedx509.a"
    COMMAND sh -c "ar xs ${ENCLAVE_LIBDIR}/libmbedtls.a"
    COMMAND sh -c "ar xs ${ENCLAVE_LIBDIR}/libmbedcrypto.a"
    COMMAND sh -c "ar rs ${ENCLAVE_LIBDIR}/liboecrypto.a *.o"
    COMMAND sh -c "rm -rf *.o")
