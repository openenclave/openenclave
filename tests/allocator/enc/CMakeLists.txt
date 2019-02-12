# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../allocator.edl enclave gen)

add_enclave(TARGET allocator_enc SOURCES enc.c ${gen})

target_include_directories(allocator_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(allocator_enc test_allocator)
