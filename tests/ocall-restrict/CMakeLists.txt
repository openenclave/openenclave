# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (UNIX)
	add_subdirectory(enc)
endif()

add_enclave_test(tests/ocall-restrict ./host ocall-restrict_host ./enc ocall-restrict_enc.signed.so)
