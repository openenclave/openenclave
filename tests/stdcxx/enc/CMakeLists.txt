# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../stdcxx.edl enclave gen)

add_enclave(TARGET stdcxx_enc CXX SOURCES enc.cpp f.cpp ${gen})
add_enclave(TARGET global_init_exception_enc CXX SOURCES
    global_init_exception.cpp ${gen})

target_compile_options(stdcxx_enc PRIVATE
    -fno-builtin-strcpy
    -fno-builtin-strcat
    -fno-builtin-memcpy
    -fno-builtin-memset
    -fno-builtin-fprintf
    -fno-builtin-printf
    -std=c++14
    )

target_include_directories(stdcxx_enc PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(global_init_exception_enc PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})
