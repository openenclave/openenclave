# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (UNIX)
	add_subdirectory(enc-debug)
        add_subdirectory(enc-no-debug)
endif()

add_enclave_test(tests/debug-mode ./host debug_host ./enc-debug debug_enc.signed.so debug)
add_enclave_test(tests/no-debug-mode ./host debug_host ./enc-no-debug no_debug_enc.signed.so nodebug)
