# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
	add_subdirectory(enc)
endif()

add_enclave_test(tests/atexit_ocall_one atexit_host atexit_enc 0)
add_enclave_test(tests/atexit_ocall_more atexit_host atexit_enc 1)
add_enclave_test(tests/atexit_ocall_ecall atexit_host atexit_enc 2)
