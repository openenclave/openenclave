# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(../thread.edl enclave gen)

add_enclave(TARGET pthread_enc CXX
    SOURCES
    enc.cpp
    cond_tests.cpp
    rwlock_tests.cpp
    ${gen})

add_enclave(TARGET oethread_enc CXX
    SOURCES
    enc.cpp
    cond_tests.cpp
    rwlock_tests.cpp
    ${gen})

target_compile_definitions(pthread_enc PRIVATE -D_PTHREAD_ENC_)

target_include_directories(pthread_enc PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})

target_include_directories(oethread_enc PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})
