# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (UNIX)
	add_subdirectory(enc)
endif()

add_enclave_test(tests/stdcxx ./host stdcxx_host ./enc stdcxx_enc OE_OK)
add_enclave_test(tests/global_init_exception ./host stdcxx_host ./enc global_init_exception_enc OE_ENCLAVE_ABORTING)
