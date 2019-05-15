# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../fs.edl enclave gen
    --edl-search-dir ../../../../posix/devices/sgxfs)

add_enclave(TARGET fs_enc SOURCES enc.cpp ${gen})

target_include_directories(fs_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

if (UNIX)
target_compile_definitions(fs_enc PRIVATE -DWANT_SGXFS=1)
endif()


target_link_libraries(fs_enc oesgxfsenclave oelibcxx oecpio oeenclave oehostfs)
