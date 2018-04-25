# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

if (ADD_WINDOWS_ENCLAVE_TESTS)
	add_subdirectory(host)
    include(add_wnd_enclave_tests)
    add_wnd_enclave_tests(report reporthost reportenc.signed.so)	#TODO : set_tests_properties(tests/report PROPERTIES SKIP_RETURN_CODE 2)
else()
add_subdirectory(enc)
add_subdirectory(host)

add_test(tests/report host/reporthost ./enc/reportenc.signed.so)
set_tests_properties(tests/report PROPERTIES SKIP_RETURN_CODE 2)
endif()