# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)
add_enclave_executable(props_enc sign.conf private.pem
    enc.c
    props.c)
target_link_libraries(props_enc oeenclave)
