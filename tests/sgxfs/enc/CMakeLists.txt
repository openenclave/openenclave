# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../test_sgxfs.edl enclave gen 
    --edl-search-dir ../../../device/fs/sgxfs)

add_executable(sgxfs_enc enc.c main.c ${gen})

target_link_libraries(sgxfs_enc oelibc oesgxfsenclave oeenclave)
