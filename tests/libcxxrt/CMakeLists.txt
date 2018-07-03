# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# add a test-case for each file listed in tests.supported
include(${CMAKE_CURRENT_LIST_DIR}/../../cmake/get_testcase_name.cmake)

add_subdirectory(host)

if(UNIX)
add_subdirectory(enc)

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

elseif (ADD_WINDOWS_ENCLAVE_TESTS)

# read tests.supported, sanitize the cpp-file, and create the test-case
file(STRINGS "tests.supported" alltests)
foreach(testcase ${alltests})
    get_testcase_name(${testcase} name "")

    if("${name}" STREQUAL "test_foreign_exceptions")
        add_enclave_test(tests/libcxxrt/${name} ./host libcxxrt_host ./enc libcxxrttest-${name}_enc.signed.so)
	else()

		file(TO_NATIVE_PATH ${LINUX_LIBCXXRT_LOG_DIR}/exp_${name}_output.log linux_log_file)
		file(TO_NATIVE_PATH ${PROJECT_BINARY_DIR}/exp_${name}_output.log linux_log_file_on_windows)
		file(TO_NATIVE_PATH ${LINUX_BIN_DIR}/libcxxrt/exp_${name}_output.log wnd_log_file)

		# Check if libcxxrt log files are generated on Linux machine at
		# given path and then copy log file from Linux machine directory to
		# Windows project binary directory.
		add_custom_command(OUTPUT ${name}_linux_logs
			COMMAND ${CMAKE_COMMAND} -E copy ${linux_log_file} ${linux_log_file_on_windows}
			DEPENDS ${linux_log_file}
			WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
		)

		# add a custom target to ALL so that this step always needs to be run if
		# this function is invoked
		add_custom_target(${name}.linux ALL
			DEPENDS ${name}_linux_logs
			)
		add_test(tests/libcxxrt/${name}
			${CMAKE_COMMAND} -E compare_files ${wnd_log_file} ${linux_log_file_on_windows})

    endif()
endforeach(testcase)

endif()#ADD_WINDOWS_ENCLAVE_TESTS
