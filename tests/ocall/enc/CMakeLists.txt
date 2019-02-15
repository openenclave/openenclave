# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# TODO: Does this need CXX?
add_enclave(TARGET ocall_enc SOURCES enc.cpp)

target_link_libraries(ocall_enc oelibcxx)
