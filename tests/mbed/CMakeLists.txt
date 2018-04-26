# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# add a test-case for each file listed in tests.supported
include(${CMAKE_CURRENT_LIST_DIR}/../../cmake/get_testcase_name.cmake)

# read tests.supported, sanitize the cpp-file, and create the test-case
file(STRINGS "tests.supported" alltests)
foreach(testcase ${alltests})

    string(FIND "${testcase}" "selftest" var)
    if(${var} GREATER 0 )
	get_testcase_name(${testcase} name "../../3rdparty/mbedtls/mbedtls/programs/test/")
	add_test(tests/mbed/${name} host/libmbedtesthost ./enc/libmbedtest-${name}.signed.so)
    elseif(${var} LESS 0)
	add_test(tests/mbed/${testcase} host/libmbedtesthost ./enc/libmbedtest_suite_${testcase}.signed.so)
    endif()

endforeach(testcase)

add_subdirectory(enc)
add_subdirectory(host)

