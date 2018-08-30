# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)

add_executable(cxxthread_enc enc.cpp cond_tests.cpp rwlock_tests.cpp props.c)

target_link_libraries(cxxthread_enc oelibcxx oeenclave)
