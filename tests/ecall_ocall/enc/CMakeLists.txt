# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_enclave(TARGET ecall_ocall_enc CXX SOURCES enc.cpp)
target_compile_features(ecall_ocall_enc PRIVATE cxx_auto_type)
