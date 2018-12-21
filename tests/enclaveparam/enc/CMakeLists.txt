# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(../enclaveparam.edl enclave gen)

add_enclave(TARGET enclaveparam_enc SOURCES enc.c ${gen})

target_include_directories(enclaveparam_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
