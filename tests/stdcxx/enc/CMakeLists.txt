# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

oeedl_file(../stdcxx.edl enclave gen)

add_enclave(TARGET stdcxx_enc UUID a228e05c-d5ce-4578-b6a3-ebbb6504daa5 CXX SOURCES enc.cpp f.cpp ${gen})
add_enclave(TARGET global_init_exception_enc UUID f891ca61-0424-4f96-9b00-e2a7164be4f5 CXX SOURCES
    global_init_exception.cpp ${gen})

target_compile_options(stdcxx_enc PRIVATE
    -fno-builtin-strcpy
    -fno-builtin-strcat
    -fno-builtin-memcpy
    -fno-builtin-memset
    -fno-builtin-fprintf
    -fno-builtin-printf
    )

target_include_directories(stdcxx_enc PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(global_init_exception_enc PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})
