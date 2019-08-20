# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_custom_target(switchless_gen DEPENDS switchless_enc_gen switchless_host_gen)

add_subdirectory(host)

if (BUILD_ENCLAVES)
	add_subdirectory(enc)
endif()

add_enclave_test(tests/switchless switchless_host switchless_enc)
