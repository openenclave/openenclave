# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# add a test-case for each file listed in tests.supported
include(${CMAKE_CURRENT_LIST_DIR}/../../cmake/get_testcase_name.cmake)


add_subdirectory(host)

if(UNIX)
	file(COPY ${PROJECT_SOURCE_DIR}/3rdparty/libcxxrt/libcxxrt/test/run_test.sh DESTINATION ${PROJECT_BINARY_DIR}/tests/libcxxrt/)
	add_subdirectory(enc)

	# Build each test in tests.supported into a normal-mode executable that is linked against 
	# the default system libraries, then run the executable to produce the expected output log
	# for that test. The log from the equivalent enclave test binary will be compared against it.
	file(STRINGS "tests.supported" alltests)
	foreach(testcase ${alltests})
		get_testcase_name(${testcase} name "")

		if("${name}" STREQUAL "test_foreign_exceptions")
			add_enclave_test(tests/libcxxrt/${name} libcxxrt_host libcxxrttest-${name}_enc)
		else()
			add_executable(${name}
				enc/${name}.cpp
			)
			target_compile_options(${name} PRIVATE
				-Wno-error
			)
			
			# Generating expected output with system-test
			add_custom_target(test-expected-${name}-output ALL
					COMMAND ${name} > ${PROJECT_BINARY_DIR}/tests/libcxxrt/exp_${name}_output.log 2>&1
					DEPENDS ${name})
			# Running Enclave test & comparing with normal test
			add_test(tests/libcxxrt/${name} run_test.sh "./host/libcxxrt_host ./enc/libcxxrttest-${name}_enc" exp_${name}_output.log ${name}_output.log)
		endif()
	endforeach(testcase)

elseif (ADD_WINDOWS_ENCLAVE_TESTS)
	get_filename_component(TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR} NAME)

	add_custom_command(OUTPUT batch_file_copy
		DEPENDS  ${CMAKE_CURRENT_SOURCE_DIR}/run.bat
		COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/run.bat ${PROJECT_BINARY_DIR}/tests/${TEST_DIR}/
		WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
	)

	add_custom_target(RunLibcxxrt.windows ALL
		DEPENDS  batch_file_copy
	)

	# read tests.supported, sanitize the cpp-file, and create the test-case
	file(STRINGS "tests.supported" alltests)
	foreach(testcase ${alltests})
		get_testcase_name(${testcase} name "")

		if("${name}" STREQUAL "test_foreign_exceptions")
			add_enclave_test(tests/libcxxrt/${name} ./host libcxxrt_host ./enc libcxxrttest-${name}_enc)
		else()
			# Logs Generation Path
			 file(TO_NATIVE_PATH ${LINUX_BIN_DIR}/libcxxrt/exp_${name}_output.log linux_log_file_path) # source path
			 file(TO_NATIVE_PATH ${PROJECT_BINARY_DIR}/tests/libcxxrt windows_log_path) # destination path

			# Check if libcxxrt log files are generated on Linux machine at
			# given path and then copy log file from Linux machine directory to
			# Windows project binary directory.
			add_custom_command(OUTPUT ${name}_expected_log
				COMMAND ${CMAKE_COMMAND} -E 
				copy ${linux_log_file_path} ${windows_log_path}/exp_${name}_output.log   # copy Linux generated  Log  
				COMMAND ${CMAKE_COMMAND} -E 
				copy ${LINUX_BIN_DIR}/libcxxrt/enc/libcxxrttest-${name}_enc 
				${PROJECT_BINARY_DIR}/tests/${TEST_DIR}/host/libcxxrttest-${name}_enc #copy Singned File to windows host folder 
				WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
			)

			add_custom_command(
				OUTPUT ${name}_output.log
				DEPENDS  ${PROJECT_BINARY_DIR}/tests/${TEST_DIR}/host/libcxxrt_host.exe
				COMMAND cmd /c run.bat "${PROJECT_BINARY_DIR}/tests/${TEST_DIR}/host/libcxxrt_host.exe" 
				"${PROJECT_BINARY_DIR}/tests/${TEST_DIR}/host/libcxxrttest-${name}_enc"  ${name}_output.log 
				WORKING_DIRECTORY ${PROJECT_BINARY_DIR}/tests/${TEST_DIR}
				)

			# add a custom target to ALL so that this step always needs to be run if
			# this function is invoked
			add_custom_target(${name}.windows ALL
				DEPENDS  ${name}_output.log ${name}_expected_log 
				)

			add_test(tests/libcxxrt/${name}
				${CMAKE_COMMAND} -E compare_files exp_${name}_output.log ${name}_output.log
				)

		endif()
	endforeach(testcase)

endif()#ADD_WINDOWS_ENCLAVE_TESTS
