# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (UNIX)
	add_subdirectory(enc)
endif()

# Test a signed enclave:
add_enclave_test(tests/initializers ./host initializers_host ./enc initializers_enc)
