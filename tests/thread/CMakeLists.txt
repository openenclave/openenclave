# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (UNIX)
	add_subdirectory(oethread_enc)
	add_subdirectory(pthread_enc)
endif()

add_enclave_test(tests/oethread 
    ./host thread_host ./oethread_enc oethread_enc)

add_enclave_test(tests/pthread 
    ./host thread_host ./pthread_enc pthread_enc)
