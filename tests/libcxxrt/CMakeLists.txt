# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if(BUILD_ENCLAVES)
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
endif()
