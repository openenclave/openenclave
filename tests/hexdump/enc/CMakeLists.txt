# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(../hexdump.edl enclave gen)

add_executable(hexdump_enc enc.c ${gen})

target_include_directories(hexdump_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(hexdump_enc oeenclave)
