# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
	add_subdirectory(enc)
endif()

add_enclave_test(tests/switchless_ocalls switchless_host switchless_enc)

add_enclave_test(tests/switchless_ecalls switchless_host switchless_enc
                 --test-ecalls)
