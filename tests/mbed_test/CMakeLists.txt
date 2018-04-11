# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# add a test-case for each file listed in tests.supported
include(${CMAKE_CURRENT_LIST_DIR}/../../cmake/get_testcase_name.cmake)

# read tests.supported, sanitize the cpp-file, and create the test-case
file(STRINGS "tests.supported" alltests)
foreach(testcase ${alltests})
    get_testcase_name(${testcase} name)
    add_test(tests/mbed_test/${name} host/libmbedtesthost ./enc/libmbedtest-${name}.signed.so)
endforeach(testcase)

add_subdirectory(enc)
add_subdirectory(host)

