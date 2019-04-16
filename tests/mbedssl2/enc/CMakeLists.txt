# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../mbedssl2.edl enclave gen --edl-search-dir ../../../device/edl)

add_enclave(TARGET mbedssl2_enc SOURCES enc.c client.c server.c ${gen})

target_compile_definitions(mbedssl2_enc PRIVATE -DOE_NEED_STDC_NAMES)

target_link_libraries(mbedssl2_enc oelibc oeenclave)
