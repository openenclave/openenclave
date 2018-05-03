# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


## This function is to add test for given host file and enclave file.
## TEST_NAME : test name for add test.
## HOST_FILE : Host application executable file name.
## ENC_FILE : Signed enclave file name.
## DESCRIPTION : For ADD_WINDOWS_ENCLAVE_TESTS enabled function will copy signed 
##			enclave file from Linux build location to windows build location 
##			after checking if both host and enclave file exists at specified 
##			location.

function(add_enclave_test TEST_NAME HOST_FILE ENC_FILE)

if (ADD_WINDOWS_ENCLAVE_TESTS)
	# custom rule to copy binary from linux
	# take a dependency on host binary to make sure it exists in addition to 
	# enc binary in linux
	add_custom_command(OUTPUT ${TEST_NAME}_windows_include
		COMMAND ${CMAKE_COMMAND} -E copy ${LINUX_BIN_DIR}/${TEST_NAME}/enc/${ENC_FILE}.signed.so ${CMAKE_CURRENT_BINARY_DIR}/host/${ENC_FILE}.signed.so
		DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/host/${HOST_FILE} ${LINUX_BIN_DIR}/${TEST_NAME}/enc/${ENC_FILE}.signed.so
		WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
		)
	# add a custom target to ALL so that this step always needs to be run if 
	# this function is invoked 
	add_custom_target(${TEST_NAME}.windows ALL
		DEPENDS ${TEST_NAME}_windows_include
		)

	# add the test (this assumes the syntax correctly copied the linux enc signed 
	# binary into the host subdir in add_custom_command; tweak it as needed)
	add_test(tests/${TEST_NAME} ${CMAKE_CURRENT_BINARY_DIR}/host/${HOST_FILE} ${CMAKE_CURRENT_BINARY_DIR}/host/${ENC_FILE}.signed.so)

elseif(UNIX)

	add_test(tests/${TEST_NAME} host/${HOST_FILE} ./enc/${ENC_FILE}.signed.so)

endif()#ADD_WINDOWS_ENCLAVE_TESTS

 # Cannot use ARGN directly with list() command,
 # so copy it to a variable first.
set (extra_macro_args ${ARGN})
list(LENGTH extra_macro_args num_extra_args)

# Did we get any optional args? if yes set SKIP_RETURN_CODE properties value using it.
if (${num_extra_args} GREATER 0)
	list(GET extra_macro_args 0 skip_ret_code_arg)
	set_tests_properties(tests/${TEST_NAME} PROPERTIES SKIP_RETURN_CODE ${skip_ret_code_arg})
endif ()

endfunction(add_enclave_test)
