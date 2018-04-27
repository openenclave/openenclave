# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

if (ADD_WINDOWS_ENCLAVE_TESTS)
	add_subdirectory(host)
    include(add_wnd_enclave_tests)
    add_wnd_enclave_tests(ocall-restrict ocall-restrict_host)
else()
add_subdirectory(enc)
add_subdirectory(host)

add_test(tests/ocall-restrict host/ocall-restrict_host ./enc/ocall-restrict_enc.signed.so)
endif()