# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
	add_subdirectory(enc)
endif()

add_enclave_test(tests/child_thread_ecall create_in_thread_host create_in_thread_enc 0)
add_enclave_test(tests/child_thread_destory create_in_thread_host create_in_thread_enc 1)
add_enclave_test(tests/child_thread_destory_check create_in_thread_host create_in_thread_enc 2)
