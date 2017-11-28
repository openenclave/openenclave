add_subdirectory(enc)
add_subdirectory(host)

# note: this is Linux-specific
add_test(NAME tests/print
	WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
	COMMAND sh -c "host/printhost ./enc/printenc.signed.so >testout.stdout 2>testout.stderr &&
		diff ${CMAKE_CURRENT_SOURCE_DIR}/printhost.stdout testout.stdout &&
		diff ${CMAKE_CURRENT_SOURCE_DIR}/printhost.stderr testout.stderr"
	)
