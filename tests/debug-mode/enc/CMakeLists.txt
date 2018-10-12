# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)

add_enclave_executable(no_debug_enc sign.conf
    enc.c
    props.c)

add_enclave_executable(debug_enc sign-debug.conf
    enc.c
    props-debug.c)

target_link_libraries(no_debug_enc oeenclave)
target_link_libraries(debug_enc oeenclave)
