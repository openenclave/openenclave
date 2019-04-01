# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../test_hostfs.edl enclave gen)

add_enclave(TARGET hostfs_enc SOURCES enc.c main.c ${gen})

target_link_libraries(hostfs_enc oelibc oeenclave)
