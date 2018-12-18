# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)
include(add_enclave_executable)

oeedl_file(../debug_mode.edl enclave gen)

add_enclave_executable(no_debug_enc sign.conf
    enc.c
    props.c
    ${gen})

add_enclave_executable(debug_enc sign-debug.conf
    enc.c
    props-debug.c
    ${gen})

target_include_directories(no_debug_enc PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})

target_include_directories(debug_enc PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(no_debug_enc oeenclave)
target_link_libraries(debug_enc oeenclave)
