# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)
add_executable(ocall-alloc_enc
    enc.cpp
    wrap.cpp
    wrap-hoststack.c
    )
target_link_libraries(ocall-alloc_enc oelibcxx oeenclave)

target_compile_features(ocall-alloc_enc PRIVATE cxx_auto_type)
