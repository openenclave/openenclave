# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)
add_executable(VectorException_enc
    enc.c
    sigill_handling.c
    init.cpp
    )

target_link_libraries(VectorException_enc oeenclave)
target_compile_options(VectorException_enc PRIVATE -Wconversion -Wpointer-arith)

target_include_directories(VectorException_enc SYSTEM PRIVATE
    ${OE_C_COMPILER_INCDIR})

