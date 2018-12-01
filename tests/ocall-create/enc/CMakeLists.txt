# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)
add_executable(ocall_create_enc enc.c)
target_link_libraries(ocall_create_enc oeenclave)
