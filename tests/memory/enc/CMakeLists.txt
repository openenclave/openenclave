# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(../memory.edl enclave gen)

add_executable(memory_enc
    basic.c
    boundaries.c
    enc.c
    stress.c
    ${gen})


target_include_directories(memory_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(memory_enc oeenclave)
target_compile_options(memory_enc PRIVATE -Wconversion -Wpointer-arith)

