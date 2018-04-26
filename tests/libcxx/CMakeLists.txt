# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# add a test-case for each file listed in tests.supported
include(${CMAKE_CURRENT_LIST_DIR}/../libc/get_testcase_name.cmake)

# read tests.supported, sanitize the cpp-file, and create the test-case
file(STRINGS "tests.supported" alltests)

if (ADD_WINDOWS_ENCLAVE_TESTS)
	add_subdirectory(host)
    include(add_wnd_enclave_tests)
    add_wnd_enclave_tests(tests_libcxx_${name})
else()
foreach(testcase ${alltests})
    get_testcase_name(${testcase} name)
    add_test(tests/libcxx/${name} host/libcxx_host ./enc/libcxxtest-${name}_enc.signed.so)
endforeach(testcase)

add_subdirectory(enc)
add_subdirectory(host)
endif()
