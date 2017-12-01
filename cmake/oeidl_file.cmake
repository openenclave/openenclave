#
# Helper function to handle IDL (gen) files
#
# Create custom-command to generate .c/.h-file for a given IDL-file
# into CMAKE_CURRENT_BINARY_DIR and set misc properties on files.
#
# Usage:
#
#       oeidl_file(
#               <idl_file> <type> <out_files_var>
#
# Arguments:
# idl_file - name of the IDL file
# type - type of files to genreate ("enclave" or "host")
# out_files_var - variable to get the generated files added to
#
function(oeidl_file IDL_FILE TYPE OUT_FILES_VAR)
	if(${TYPE} STREQUAL "enclave")
		set(type_id "t")
	elseif(${TYPE} STREQUAL "host")
		set(type_id "u")
	else()
		message(FATAL_ERROR "unknown IDL generation type ${TYPE} - must be \"enclave\" or \"host\"")
	endif()

	get_filename_component(idl_base ${IDL_FILE} NAME_WE)
	get_filename_component(in_path ${IDL_FILE} PATH)

	set(h_file ${CMAKE_CURRENT_BINARY_DIR}/${idl_base}_${type_id}.h)
	set(c_file ${CMAKE_CURRENT_BINARY_DIR}/${idl_base}_${type_id}.c)

	add_custom_command(
		OUTPUT ${h_file} ${c_file}
		DEPENDS ${IDL_FILE}
		COMMAND oegen -${type_id} -d ${CMAKE_CURRENT_BINARY_DIR} ${IDL_FILE}
		WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
		)

	set_source_files_properties(
		${h_file} ${c_file}
		PROPERTIES GENERATED TRUE
		)
	set_source_files_properties(
		${IDL_FILE}
		PROPERTIES HEADER_FILE_ONLY TRUE
		)

	# append h_file,c_file to output var
	list(APPEND ${OUT_FILES_VAR} ${h_file} ${c_file})
	set(${OUT_FILES_VAR} ${${OUT_FILES_VAR}} PARENT_SCOPE)

	#message("h_file=${h_file} c_file=${c_file} IDL_FILE=${IDL_FILE} OUT_FILES=${${OUT_FILES_VAR}}")
endfunction(oeidl_file)

