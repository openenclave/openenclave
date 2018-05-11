# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (UNIX)
	add_subdirectory(enc)
endif()

# Test a signed enclave:
add_enclave_test(tests/props ./host props_host ./enc props_enc.signed.so signed)

# Test unsigned enclave:
add_enclave_test(tests/props_unsigned ./host props_host ./enc propsenc unsigned)
