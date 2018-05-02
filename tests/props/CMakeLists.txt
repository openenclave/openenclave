# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (UNIX)
	add_subdirectory(enc)

	# Test unsigned enclave:
	add_test(tests/props_unsigned host/props_host ./enc/propsenc unsigned)		#TODO : Make it generic so that this will be executed for windows also.
endif()

# Test a signed enclave:
add_enclave_test(props props_host props_enc)
