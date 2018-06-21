# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

if(NOT EXISTS ${PROJECT_BINARY_DIR}/3rdparty/libcxxrt-test/build)
    file(MAKE_DIRECTORY ${PROJECT_BINARY_DIR}/3rdparty/libcxxrt-test/build)
endif()

include (ExternalProject)
ExternalProject_Add(libcxxrt-test
    DOWNLOAD_COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${PROJECT_SOURCE_DIR}/3rdparty/libcxxrt/libcxxrt ${PROJECT_BINARY_DIR}/3rdparty/libcxxrt-test
    CONFIGURE_COMMAND cd ${PROJECT_BINARY_DIR}/3rdparty/libcxxrt-test/build && cmake ..
    BUILD_COMMAND $(MAKE) -C ${PROJECT_BINARY_DIR}/3rdparty/libcxxrt-test/build
    # copy libs & test scripts
    INSTALL_COMMAND ${CMAKE_COMMAND} -E copy
        ${PROJECT_BINARY_DIR}/3rdparty/libcxxrt-test/build/lib/libcxxrt.a ${PROJECT_BINARY_DIR}/tests/libcxxrt/libcxxrt-test.a
        COMMAND ${CMAKE_COMMAND} -E copy
        ${PROJECT_SOURCE_DIR}/3rdparty/libcxxrt/libcxxrt/test/run_test.sh ${PROJECT_BINARY_DIR}/tests/libcxxrt/
)

# add a test-case for each file listed in tests.supported
include(${CMAKE_CURRENT_LIST_DIR}/../../cmake/get_testcase_name.cmake)

# read tests.supported, sanitize the cpp-file, and create the test-case
file(STRINGS "tests.supported" alltests)
foreach(testcase ${alltests})
    get_testcase_name(${testcase} name "")

    if("${name}" STREQUAL "test_foreign_exceptions")
        add_enclave_test(tests/libcxxrt/${name} ./host libcxxrt_host ./enc libcxxrttest-${name}_enc.signed.so)
    else()
        add_executable(${name}
            enc/${name}.cpp
        )
        add_dependencies(${name} libcxxrt-test)
        target_compile_options(${name} PRIVATE
            -Wno-error
        )
        target_include_directories(${name} PRIVATE
            ${PROJECT_SOURCE_DIR}/3rdparty/libcxxrt/libcxxrt/src
            ${PROJECT_BINARY_DIR}/output/include/openenclave/libcxx
            ${PROJECT_BINARY_DIR}/output/include/openenclave/libc
        )
        target_link_libraries(${name} ${PROJECT_BINARY_DIR}/tests/libcxxrt/libcxxrt-test.a gcc_s dl c)
# Generating expected output with system-test
        add_custom_target(test-expected-${name}-output ALL
                COMMAND ${name} > ${PROJECT_BINARY_DIR}/tests/libcxxrt/exp_${name}_output.log 2>&1
                DEPENDS ${name})
# Running Enclave test & comparing with normal test
        add_test(tests/libcxxrt/${name} run_test.sh "./host/libcxxrt_host ./enc/libcxxrttest-${name}_enc.signed.so" exp_${name}_output.log ${name}_output.log)
    endif()
endforeach(testcase)
add_subdirectory(enc)
add_subdirectory(host)
