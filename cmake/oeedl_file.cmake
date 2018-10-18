# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
# Helper function to handle EDL (gen) files
#
# Create custom-command to generate .c/.h-file for a given EDL-file
# into CMAKE_CURRENT_BINARY_DIR and set misc properties on files.
#
# Usage:
#
#       oeedl_file(
#               <edl_file> <type> <out_files_var>
#
# Arguments:
# edl_file - name of the EDL file
# type - type of files to genreate ("enclave" or "host")
# out_files_var - variable to get the generated files added to
#
function(oeedl_file EDL_FILE TYPE OUT_FILES_VAR)
	if(${TYPE} STREQUAL "enclave")
		set(type_id "t")
		set(type_opt "--trusted")
		set(dir_opt  "--trusted-dir")
	elseif(${TYPE} STREQUAL "host")
		set(type_id "u")
		set(type_opt "--untrusted")
		set(dir_opt  "--untrusted-dir")
	else()
		message(FATAL_ERROR "unknown EDL generation type ${TYPE} - must be \"enclave\" or \"host\"")
	endif()

	get_filename_component(idl_base ${EDL_FILE} NAME_WE)
	get_filename_component(in_path ${EDL_FILE} PATH)

	set(h_file ${CMAKE_CURRENT_BINARY_DIR}/${idl_base}_${type_id}.h)
	set(c_file ${CMAKE_CURRENT_BINARY_DIR}/${idl_base}_${type_id}.c)

	add_custom_command(
		OUTPUT ${h_file} ${c_file}
		# Temorary workaround:
		# Add explict dependency to oeedger8r binary.
		# oeedger8r custom target cannot declare its output binary.
		# Without the explicity dependecy to the binary below, running make on a test
		# will rebuild the edger8r if it is out of date, but will not invoke the newly build edger8r
		# on the edl file.
		DEPENDS ${EDL_FILE} oeedger8r ${OE_BINDIR}/oeedger8r
		COMMAND ${OE_BINDIR}/oeedger8r ${type_opt} ${dir_opt} ${CMAKE_CURRENT_BINARY_DIR} ${EDL_FILE}
		WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
		)

	set_source_files_properties(
		${h_file} ${c_file}
		PROPERTIES GENERATED TRUE
		)
	set_source_files_properties(
		${EDL_FILE}
		PROPERTIES HEADER_FILE_ONLY TRUE
		)

	# append h_file,c_file to output var
	list(APPEND ${OUT_FILES_VAR} ${h_file} ${c_file})
	set(${OUT_FILES_VAR} ${${OUT_FILES_VAR}} PARENT_SCOPE)

	#message("h_file=${h_file} c_file=${c_file} EDL_FILE=${EDL_FILE} OUT_FILES=${${OUT_FILES_VAR}}")
endfunction(oeedl_file)

