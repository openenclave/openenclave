# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)
add_enclave_executable(propsenc sign.conf private.pem
    enc.c
    props.c)
target_link_libraries(propsenc oecore)
