# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

if (ADD_WINDOWS_ENCLAVE_TESTS)
	add_subdirectory(host)
    include(add_wnd_enclave_tests)
    add_wnd_enclave_tests(tester)
else()
add_subdirectory(enc)
add_subdirectory(host)

add_test(tests/tester host/tester_host ./enc/tester_enc.signed.so)
endif()