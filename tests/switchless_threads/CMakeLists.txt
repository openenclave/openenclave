# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_custom_target(switchless_threads_gen DEPENDS switchless_threads_enc_gen switchless_threads_host_gen)

add_subdirectory(host)

if (BUILD_ENCLAVES)
	add_subdirectory(enc)
endif()

add_enclave_test(tests/switchless_threads switchless_threads_host switchless_threads_enc)