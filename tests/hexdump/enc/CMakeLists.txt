# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../hexdump.edl enclave gen)

add_enclave(TARGET hexdump_enc SOURCES enc.c ${gen})

target_include_directories(hexdump_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
