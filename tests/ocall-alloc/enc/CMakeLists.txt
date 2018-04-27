# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)
add_enclave_executable(ocall-alloc-enc sign.conf private.pem
    enc.cpp
    wrap.cpp
    wrap-hoststack.c
    )
target_link_libraries(ocall-alloc-enc oelibcxx)

target_compile_features(ocall-alloc-enc PRIVATE cxx_auto_type)

