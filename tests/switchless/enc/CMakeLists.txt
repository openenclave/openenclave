# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../switchless.edl enclave gen)

add_enclave(TARGET switchless_enc UUID d497e154-9e8e-4029-a53d-c0a36533fb95 SOURCES enc.c ${gen})

target_include_directories(switchless_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(switchless_enc oelibc)
