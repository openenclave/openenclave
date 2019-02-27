# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../ocall.edl enclave gen)

add_enclave(TARGET ocall_enc SOURCES enc.cpp ${gen})

target_include_directories(ocall_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(ocall_enc oelibcxx)
