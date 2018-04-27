# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

if (ADD_WINDOWS_ENCLAVE_TESTS)
	add_subdirectory(host)
    include(add_wnd_enclave_tests)
    add_wnd_enclave_tests(props)
else()

add_subdirectory(enc)
add_subdirectory(host)

# Test unsigned enclave:
add_test(tests/props2 host/props_host ./enc/propsenc unsigned)

# Test a signed enclave:
add_test(tests/props1 host/props_host ./enc/props_enc.signed.so signed)
endif()
