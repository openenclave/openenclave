# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (UNIX)
	add_subdirectory(enc)
endif()

add_enclave_test(tests/polling_corelibc
    polling_test_host
    polling_test_enc
    "${CMAKE_CURRENT_BINARY_DIR}"
    corelibc)

add_enclave_test(
    tests/polling_libc
    polling_test_host
    polling_test_enc
    "${CMAKE_CURRENT_BINARY_DIR}"
    libc)
