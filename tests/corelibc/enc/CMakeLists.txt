# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../corelibc.edl enclave gen --edl-search-dir ../../../device/edl)

add_enclave(TARGET corelibc_enc SOURCES enc.c ${gen})

# Find standard-C includes in the corelibc direcrtory.
target_include_directories(corelibc_enc PRIVATE
    ${PROJECT_SOURCE_DIR}/include/openenclave/corelibc)

target_link_libraries(corelibc_enc oeenclave)
