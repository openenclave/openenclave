# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (UNIX)
	add_subdirectory(enc)
endif()

add_enclave_test(tests/polling2 polling_test_host polling_test_enc USE_CORELIBC)

#add_enclave_test(tests/polling1 polling_test_host polling_test_enc USE_LIBC)
