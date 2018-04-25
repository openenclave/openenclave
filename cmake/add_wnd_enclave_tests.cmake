## ATTN: Instead of doing a bulk copy and then writing a custom action to 
## enumerate all tests to add_test, create a custom task that you can use 
## on a per test basis, for example:

function(add_wnd_enclave_tests TESTNAME EXE_FILE SIGNED_BIN)

	Message("add_wnd_enclave_tests called for .....................")
	Message(${TESTNAME})
	Message(${LINUX_BIN_DIR}/${TESTNAME}/enc/${SIGNED_BIN})
	Message(${CMAKE_CURRENT_BINARY_DIR}/host/${SIGNED_BIN})


	# custom rule to copy binary from linux
	# take a dependency on host binary to make sure it exists in addition to 
	# enc binary in linux
	add_custom_command(OUTPUT ${TESTNAME}_windows_include
		COMMAND ${CMAKE_COMMAND} -E copy ${LINUX_BIN_DIR}/${TESTNAME}/enc/${SIGNED_BIN} ${CMAKE_CURRENT_BINARY_DIR}/host/${SIGNED_BIN}
		DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/host/${EXE_FILE} ${LINUX_BIN_DIR}/${TESTNAME}/enc/${SIGNED_BIN}
		WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
		)
	# add a custom target to ALL so that this step always needs to be run if 
	# this function is invoked 
	add_custom_target(${TESTNAME}.windows ALL
		DEPENDS ${TESTNAME}_windows_include
		)

	# add the test (this assumes the syntax correctly copied the linux enc signed 
	# binary into the host subdir in add_custom_command; tweak it as needed)
	add_test(tests/${TESTNAME} ${CMAKE_CURRENT_BINARY_DIR}/host/${EXE_FILE} ${CMAKE_CURRENT_BINARY_DIR}/host/${SIGNED_BIN})
		
endfunction(add_wnd_enclave_tests)