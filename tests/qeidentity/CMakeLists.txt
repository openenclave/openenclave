# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (UNIX)
	add_subdirectory(enc)
endif()

# Run all tests
add_enclave_test(tests/qeidentity qeidentity_host qeidentity_enc)
set_tests_properties(tests/qeidentity PROPERTIES SKIP_RETURN_CODE 2)
