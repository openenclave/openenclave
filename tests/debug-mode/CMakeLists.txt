# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (UNIX)
    add_subdirectory(enc)

	add_enclave_test(tests/debug-unsigned ./host debug_host ./enc debug_enc debug unsigned)
	set_tests_properties(tests/debug-unsigned PROPERTIES SKIP_RETURN_CODE 2)
endif()

add_enclave_test(tests/debug-signed ./host debug_host ./enc debug_enc.signed.so debug signed)
add_enclave_test(tests/nodebug-signed ./host debug_host ./enc no_debug_enc.signed.so nodebug signed)
add_enclave_test(tests/nodebug-unsigned ./host debug_host ./enc no_debug_enc nodebug unsigned)

set_tests_properties(tests/debug-signed PROPERTIES SKIP_RETURN_CODE 2)
set_tests_properties(tests/nodebug-signed PROPERTIES SKIP_RETURN_CODE 2)
set_tests_properties(tests/nodebug-unsigned PROPERTIES SKIP_RETURN_CODE 2)
