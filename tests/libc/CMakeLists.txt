# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# add a test-case for each file listed in tests.supported
include(${CMAKE_CURRENT_LIST_DIR}/../../cmake/get_testcase_name.cmake)

# read tests.supported, sanitize the c-file, and create the test-case
if (ENABLE_FULL_LIBC_TESTS)
    file(STRINGS "tests.supported" alltests)
else()
    file(STRINGS "tests.supported.default" alltests)
endif()

add_subdirectory(host)

if (UNIX)
	add_subdirectory(enc)
endif()

foreach(testcase ${alltests})
    get_testcase_name(${testcase} name "../../3rdparty/musl/libc-test/src/")
	add_enclave_test(tests/libc/${name} ./host libc_host ./enc libctest-${name}_enc)
endforeach(testcase)
