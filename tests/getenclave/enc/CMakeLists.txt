# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


oeedl_file(../getenclave.edl enclave gen)

add_enclave(TARGET getenclave_enc SOURCES enc.c ${gen})

target_include_directories(getenclave_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
