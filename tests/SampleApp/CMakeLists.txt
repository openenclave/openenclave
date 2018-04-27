# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

if (ADD_WINDOWS_ENCLAVE_TESTS)
	add_subdirectory(SampleAppHost)
    include(add_wnd_enclave_tests)
    add_wnd_enclave_tests(SampleApp SampleAppHost)
else()
add_subdirectory(SampleApp)
add_subdirectory(SampleAppHost)

add_test(tests/SampleApp SampleAppHost/SampleAppHost SampleApp/SampleApp.signed.so)
endif()