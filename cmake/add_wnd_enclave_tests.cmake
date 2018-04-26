## This function is used on Windows only.
## This function is called to copy linux signed.so file from linux to corresponding windows build location and will add tests for it.
## TESTNAME : test name for which corresponding signed.so file should be copied from linux and this name is also used for add test.

function(add_wnd_enclave_tests TESTNAME)

	# custom rule to copy binary from linux
	# take a dependency on host binary to make sure it exists in addition to 
	# enc binary in linux
	add_custom_command(OUTPUT ${TESTNAME}_windows_include
		COMMAND ${CMAKE_COMMAND} -E copy ${LINUX_BIN_DIR}/${TESTNAME}/enc/${TESTNAME}_enc.signed.so ${CMAKE_CURRENT_BINARY_DIR}/host/${TESTNAME}_enc.signed.so
		DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/host/${TESTNAME}_host ${LINUX_BIN_DIR}/${TESTNAME}/enc/${TESTNAME}_enc.signed.so
		WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
		)
	# add a custom target to ALL so that this step always needs to be run if 
	# this function is invoked 
	add_custom_target(${TESTNAME}.windows ALL
		DEPENDS ${TESTNAME}_windows_include
		)

	# add the test (this assumes the syntax correctly copied the linux enc signed 
	# binary into the host subdir in add_custom_command; tweak it as needed)
	add_test(tests/${TESTNAME} ${CMAKE_CURRENT_BINARY_DIR}/host/${TESTNAME}_host ${CMAKE_CURRENT_BINARY_DIR}/host/${TESTNAME}_enc.signed.so)
		
endfunction(add_wnd_enclave_tests)