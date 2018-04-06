# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# add a test-case for each file listed in tests.supported
include(${CMAKE_CURRENT_LIST_DIR}/../libc/get_testcase_name.cmake)

# read tests.supported, sanitize the cpp-file, and create the test-case
if (ENABLE_FULL_LIBCXX_TESTS)
    file(STRINGS "tests.supported.all" alltests)
else()
    file(STRINGS "tests.supported" alltests)
endif()

foreach(testcase ${alltests})
    get_testcase_name(${testcase} name)
    add_test(tests/libcxx/${name} host/libcxxhost ./enc/libcxxtest-${name}.signed.so)
endforeach(testcase)

add_subdirectory(enc)
add_subdirectory(host)
