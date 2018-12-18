# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


## This function is to add test for given host file and enclave file.
## TEST_NAME	: test name for add test.
## HOST_FILE	: Host application executable file name.
## ENC_FILE		: Signed/UnSigned enclave file name.
## DESCRIPTION : For ADD_WINDOWS_ENCLAVE_TESTS enabled function will copy signed 
##			enclave file from Linux build location to windows build location 
##			after checking if both host and enclave file exists at specified 
##			location.
##			NOTE : Any additional arguments after ENC_FILE argument are passed
##			directly to add_test.

function(add_enclave_test TEST_NAME HOST_FILE ENC_FILE)

if (ADD_WINDOWS_ENCLAVE_TESTS)

	# get test directory name only, so that it can be used to
	# make complete path.
	get_filename_component(TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR} NAME)


        # (HACK1)Ideally, the path to the enclave should be $<TARGET_FILE:${ENC_FILE}>
        # However, for windows, the Linux build of the enclave is used for testing.
        # Instead of passing in "enc" as the subpath,
        # we are using "enc" as the default enclave subpath  
        # and "host" as the default host subpath.
        # This hack can be removed when CMake on Windows produces ELF enclaves.
        set(TEST_ENCSUBPATH enc)
        set(TEST_HOSTSUBPATH host)

        # (HACK2)This is a hack to figure out the target name for the linux enclave
        # Ideally, the name of the enclave is found by $<TARGET_FILE:${ENC_FILE}>
        # However, on windows, testing is done with the Linux build of the enclave.
        # This hack can be removed when CMake on Windows produces ELF enclaves.
        set(TEST_ENCFILE ${ENC_FILE})
	if(ENC_FILE MATCHES ".*_signed")
           string(REGEX REPLACE "_signed" ".signed" TEST_ENCFILE ${ENC_FILE})
        endif()

	# custom rule to copy binary from linux
	# take a dependency on host binary to make sure it exists in addition to 
	# enc binary in linux
	add_custom_command(OUTPUT ${TEST_NAME}_windows_include
		COMMAND ${CMAKE_COMMAND} -E copy ${LINUX_BIN_DIR}/${TEST_DIR}/${TEST_ENCSUBPATH}/${TEST_ENCFILE} ${CMAKE_CURRENT_BINARY_DIR}/${TEST_HOSTSUBPATH}/${TEST_ENCFILE}
		DEPENDS $<TARGET_FILE:${HOST_FILE}> ${LINUX_BIN_DIR}/${TEST_DIR}/${TEST_ENCSUBPATH}/${TEST_ENCFILE}
		WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
		)

	# add a custom target to ALL so that this step always needs to be run if 
	# this function is invoked 
	get_filename_component(TEST_NAME_WITHOUT_SLASH ${TEST_NAME} NAME)
	add_custom_target(${TEST_NAME_WITHOUT_SLASH}.windows ALL
		DEPENDS ${TEST_NAME}_windows_include
		)

	add_test(NAME ${TEST_NAME} COMMAND $<TARGET_FILE:${HOST_FILE}> ${CMAKE_CURRENT_BINARY_DIR}/${TEST_HOSTSUBPATH}/${TEST_ENCFILE} ${ARGN})

elseif (UNIX)
        add_test(NAME ${TEST_NAME} COMMAND $<TARGET_FILE:${HOST_FILE}> $<TARGET_FILE:${ENC_FILE}> ${ARGN})
endif()

endfunction(add_enclave_test)
