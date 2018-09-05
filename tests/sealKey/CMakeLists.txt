# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (UNIX)
	add_subdirectory(enc)
endif()

add_enclave_test(tests/sealKey ./host sealKey_host ./enc sealKey_enc)
set_tests_properties(tests/sealKey PROPERTIES SKIP_RETURN_CODE 2)
