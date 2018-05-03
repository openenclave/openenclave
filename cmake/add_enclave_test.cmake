# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


## This function is to add test for given host file and enclave file.
## TEST_NAME	: test name for add test.
## HOST_SUBPATH : Path of host file directory.
## HOST_FILE	: Host application executable file name.
## ENC_SUBPATH	: Path of enclave file directory.
## ENC_FILE		: Signed/UnSigned enclave file name.
## DESCRIPTION : For ADD_WINDOWS_ENCLAVE_TESTS enabled function will copy signed 
##			enclave file from Linux build location to windows build location 
##			after checking if both host and enclave file exists at specified 
##			location.

function(add_enclave_test TEST_NAME HOST_SUBPATH HOST_FILE ENC_SUBPATH ENC_FILE)

if (ADD_WINDOWS_ENCLAVE_TESTS)

	# get test directory name only, remove prefix 'tests/' so that it
	# can be used to make complete path.
	get_filename_component(TEST_DIR ${TEST_NAME} NAME)

	# custom rule to copy binary from linux
	# take a dependency on host binary to make sure it exists in addition to 
	# enc binary in linux
	add_custom_command(OUTPUT ${TEST_NAME}_windows_include
		COMMAND ${CMAKE_COMMAND} -E copy ${LINUX_BIN_DIR}/${TEST_DIR}/${ENC_SUBPATH}/${ENC_FILE} ${CMAKE_CURRENT_BINARY_DIR}/${HOST_SUBPATH}/${ENC_FILE}
		DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${HOST_SUBPATH}/${HOST_FILE} ${LINUX_BIN_DIR}/${TEST_DIR}/${ENC_SUBPATH}/${ENC_FILE}
		WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
		)

	# add a custom target to ALL so that this step always needs to be run if 
	# this function is invoked 
	add_custom_target(${TEST_DIR}.windows ALL
		DEPENDS ${TEST_NAME}_windows_include
		)

endif()#ADD_WINDOWS_ENCLAVE_TESTS

add_test(${TEST_NAME} ${HOST_SUBPATH}/${HOST_FILE} ${HOST_SUBPATH}/${ENC_FILE})

endfunction(add_enclave_test)
