# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

if (ADD_WINDOWS_ENCLAVE_TESTS)
	add_subdirectory(host)
    include(add_wnd_enclave_tests)
    add_wnd_enclave_tests(sealKey sealKey_host)
	#TODO : set_tests_properties(sealKey PROPERTIES SKIP_RETURN_CODE 2)
else()

add_subdirectory(enc)
add_subdirectory(host)

add_test(tests/sealKey host/sealKey_host ./enc/sealKey_enc.signed.so)
set_tests_properties(tests/sealKey PROPERTIES SKIP_RETURN_CODE 2)
endif()
