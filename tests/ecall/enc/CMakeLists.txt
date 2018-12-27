# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# TODO: Does this need CXX?

oeedl_file(../ecall.edl enclave gen)

add_enclave(TARGET ecall_enc SOURCES enc.cpp ${gen})

target_include_directories(ecall_enc PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})
