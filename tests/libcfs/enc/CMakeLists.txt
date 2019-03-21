# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../libcfs.edl enclave gen)

#add_enclave(TARGET libcfs_enc SOURCES enc.c ${gen})

add_executable(libcfs_enc enc.c main.c ${gen})

target_link_libraries(libcfs_enc oelibc oesgxfsenclave oeenclave)
