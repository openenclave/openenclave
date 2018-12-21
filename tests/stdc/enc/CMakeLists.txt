# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)

oeedl_file(../stdc.edl enclave gen)

# TODO: Does this need CXX?
add_enclave(TARGET stdc_enc SOURCES enc.cpp ${gen})

target_compile_options(stdc_enc PRIVATE
    -fno-builtin-strcpy
    -fno-builtin-strcat
    -fno-builtin-memcpy
    -fno-builtin-memset
    )

target_include_directories(stdc_enc PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})
