# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)
add_enclave_executable(abortStatus_enc sign.conf private.pem
    enc.cpp
    ../../ecall_ocall/crc32.cpp
    )

target_compile_features(abortStatus_enc PRIVATE cxx_generalized_initializers)
target_link_libraries(abortStatus_enc oelibcxx oeenclave)
