# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../fs.edl enclave gen --edl-search-dir ../../../device/fs/sgxfs)

#oeedl_file(../../../device/fs/sgxfs/sgx_tprotected_fs.edl)

#add_enclave(TARGET fs_enc SOURCES enc.c ${gen})

add_executable(fs_enc enc.cpp libcex.cpp ${gen})

target_include_directories(fs_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(fs_enc oelibcxx oesgxfsenclave oecpio oeenclave)
