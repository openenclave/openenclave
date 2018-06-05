# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)
add_enclave_executable(ecall_enc sign.conf private.pem
    enc.cpp
    )
target_link_libraries(ecall_enc oecore oelibc)
