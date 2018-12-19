# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


add_enclave(TARGET pthread_enc
    SOURCES
    enc_pthread.cpp
    cond_tests_pthread.cpp
    rwlock_tests_pthread.cpp)

add_enclave(TARGET oethread_enc
    SOURCES
    enc_oethread.cpp
    cond_tests_oethread.cpp
    rwlock_tests_oethread.cpp)

target_link_libraries(pthread_enc oelibcxx oeenclave)
target_link_libraries(oethread_enc oelibcxx oeenclave)
