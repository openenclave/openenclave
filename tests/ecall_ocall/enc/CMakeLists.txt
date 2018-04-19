# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)
add_cxx_enclave_executable(ecall_ocall_enc sign.conf private.pem
    ../crc32.cpp
    enc.cpp
    )

target_compile_features(ecall_ocall_enc PRIVATE cxx_auto_type)
target_link_libraries(ecall_ocall_enc oelibcxx)
