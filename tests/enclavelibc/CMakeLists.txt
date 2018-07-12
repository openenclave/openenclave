# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (UNIX)
	add_subdirectory(enc)
endif()

add_enclave_test(
    tests/enclavelibc ./host enclavelibc_host ./enc enclavelibc_enc.signed.so)
