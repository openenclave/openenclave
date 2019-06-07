# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../test_dup.edl enclave gen --edl-search-dir ../../../device/edl)

add_enclave(TARGET dup_enc SOURCES enc.c main.c ${gen})

target_link_libraries(dup_enc oelibc oehostfs oeenclave)
