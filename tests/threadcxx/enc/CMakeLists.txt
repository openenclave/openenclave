# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../threadcxx.edl enclave gen)

add_enclave(TARGET threadcxx_enc CXX SOURCES enc.cpp cond_tests.cpp ${gen})

target_include_directories(threadcxx_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})
