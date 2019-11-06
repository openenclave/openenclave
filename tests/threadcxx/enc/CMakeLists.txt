# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

oeedl_file(../threadcxx.edl enclave gen)

add_enclave(TARGET threadcxx_enc UUID 209fac8d-dea1-4ed6-8160-5d6f3fdac61d CXX SOURCES enc.cpp cond_tests.cpp ${gen})

target_include_directories(threadcxx_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})
