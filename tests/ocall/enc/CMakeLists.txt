# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)
add_enclave_executable(ocall_enc sign.conf private.pem
    enc.cpp
    )
target_link_libraries(ocall_enc oecore)
