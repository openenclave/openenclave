# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)

add_executable(echo_enc enc.c)

target_link_libraries(echo_enc oeenclave)
