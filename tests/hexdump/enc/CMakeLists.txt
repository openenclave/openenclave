# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)
include(add_enclave_executable)

oeedl_file(../hexdump.edl enclave gen)

add_executable(hexdump_enc enc.c ${gen})

target_include_directories(hexdump_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(hexdump_enc oeenclave)
target_compile_options(hexdump_enc PRIVATE -Wconversion -Wpointer-arith)
