# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
	add_subdirectory(enc)
endif()

add_enclave_test(tests/oethread 
    thread_host oethread_enc)

add_enclave_test(tests/pthread 
    thread_host pthread_enc)
