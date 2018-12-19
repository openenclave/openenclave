# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(ecall_ocall_enc enc.cpp)

target_compile_features(ecall_ocall_enc PRIVATE cxx_auto_type)
target_link_libraries(ecall_ocall_enc oelibcxx oeenclave)
