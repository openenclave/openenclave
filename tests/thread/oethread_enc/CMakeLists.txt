# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)
add_executable(oethread_enc
    enc.cpp
    cond_tests.cpp
    rwlock_tests.cpp)

target_link_libraries(oethread_enc oelibcxx oeenclave)
