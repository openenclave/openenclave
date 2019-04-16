# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../mbedssl.edl enclave gen --edl-search-dir ../../../device/edl)

add_enclave(TARGET mbedssl_enc SOURCES enc.c client.c server.c ${gen})

target_include_directories(mbedssl_enc PRIVATE
    ${PROJECT_SOURCE_DIR}/include/openenclave/corelibc)

target_compile_definitions(mbedssl_enc PRIVATE -DOE_NEED_STDC_NAMES)

target_link_libraries(mbedssl_enc oeenclave)
