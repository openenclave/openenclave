
# Helper function to create enclave binary
#
# Generates a target for an enclave binary
#
# Usage:
#
#	add_enclave_executable(
#		<name> <signconffile> <signkeyfile>
#		source1 [source2...]
#
# Target properties can be set on <name>, see add_executable for details.
#
# Restrictions: A number of subtleties are not handled, such as
# - RUNTIME_OUTPUT_DIRECTORY property is not handled correctly
# - the resulting binary name is not reflected by the target
#   (complicating install rules)
#
function(add_enclave_executable BIN SIGNCONF KEYFILE)
	add_executable(${BIN} ${ARGN})

	# enclaves depend on the oeenclave lib
	target_link_libraries(${BIN} oeenclave)

	# custom rule to sign the binary
	add_custom_command(OUTPUT ${BIN}.signed.so
		COMMAND oesign $<TARGET_FILE:${BIN}> ${SIGNCONF} ${KEYFILE}
		DEPENDS oesign ${BIN} ${SIGNCONF} ${KEYFILE}
		WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
		)
	# signed binary is a default target
	add_custom_target(${BIN}-signed ALL
		DEPENDS ${BIN}.signed.so
		)
endfunction(add_enclave_executable)
