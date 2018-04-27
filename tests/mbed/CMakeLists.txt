# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# add a test-case for each file listed in tests.supported
include(${CMAKE_CURRENT_LIST_DIR}/../../cmake/get_testcase_name.cmake)

# read tests.supported, sanitize the cpp-file, and create the test-case
file(STRINGS "tests.supported" alltests)

if (ADD_WINDOWS_ENCLAVE_TESTS)
	
include(add_wnd_enclave_tests)
foreach(testcase ${alltests})
    get_testcase_name(${testcase} name "../../3rdparty/mbedtls/mbedtls/programs/test/")
    add_wnd_enclave_tests(libmbedtest-${name})# host/libmbedtest_host ./enc/libmbedtest-${name}.signed.so)
endforeach(testcase)

add_subdirectory(host)

else()

foreach(testcase ${alltests})
    get_testcase_name(${testcase} name "../../3rdparty/mbedtls/mbedtls/programs/test/")
    add_test(tests/mbed/${name} host/libmbedtest_host ./enc/libmbedtest-${name}_enc.signed.so)
endforeach(testcase)

add_subdirectory(enc)
add_subdirectory(host)

endif()