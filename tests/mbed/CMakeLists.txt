# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# add a test-case for each file listed in tests.supported
include(${CMAKE_CURRENT_LIST_DIR}/../../cmake/get_testcase_name.cmake)

# read tests.supported, sanitize the cpp-file, and create the test-case
file(STRINGS "tests_suites.supported" alltests)
foreach(testcase ${alltests})
    add_test(tests/mbed/${testcase} host/libmbedtesthost ./enc/libmbedtest_suite_${testcase}.signed.so)
endforeach(testcase)

add_subdirectory(enc)
add_subdirectory(host)

