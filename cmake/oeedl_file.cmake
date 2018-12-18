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
#               <edl_file> <type> <out_files_var> [--edl-search-dir dir]
#
# Arguments:
# edl_file - name of the EDL file
# type - type of files to genreate ("enclave" or "host" or "enclave-headers" or "host-headers")
# out_files_var - variable to get the generated files added to
# --edl-search-dir dir - Additional folder relative to the source directory to look for imported edl files.
function(oeedl_file EDL_FILE TYPE OUT_FILES_VAR)
	get_filename_component(idl_base ${EDL_FILE} NAME_WE)
	get_filename_component(in_path ${EDL_FILE} PATH)

	if(${TYPE} STREQUAL "enclave")
		set(type_id "t")
		set(type_opt "--trusted")
		set(dir_opt  "--trusted-dir")
		set(headers_only "")
		set(c_file ${CMAKE_CURRENT_BINARY_DIR}/${idl_base}_${type_id}.c)
	elseif(${TYPE} STREQUAL "host")
		set(type_id "u")
		set(type_opt "--untrusted")
		set(dir_opt  "--untrusted-dir")
		set(headers_only "")
		set(c_file ${CMAKE_CURRENT_BINARY_DIR}/${idl_base}_${type_id}.c)
	elseif(${TYPE} STREQUAL "enclave-headers")
		set(type_id "t")
		set(type_opt "--trusted")
		set(dir_opt  "--trusted-dir")
		set(headers_only "--header-only")
		set(c_file "")
	elseif(${TYPE} STREQUAL "host-headers")
		set(type_id "u")
		set(type_opt "--untrusted")
		set(dir_opt  "--untrusted-dir")
		set(headers_only "--header-only")
		set(c_file "")
	else()
		message(FATAL_ERROR "unknown EDL generation type ${TYPE} - must be \"enclave\" or \"host\"")
	endif()

	if(${ARGC} EQUAL 5)
		if (${ARGV3} STREQUAL "--edl-search-dir")
			set(edl_search_path --search-path ${CMAKE_CURRENT_SOURCE_DIR}/${ARGV4})
		endif()
	endif()


	set(h_file ${CMAKE_CURRENT_BINARY_DIR}/${idl_base}_${type_id}.h)

	if (UNIX)
		set(OEEDGER8R_COMMAND oeedger8r)
	else()
		set(OEEDGER8R_COMMAND oeedger8r.exe)
	endif()

	add_custom_command(
		OUTPUT ${h_file} ${c_file}
		# NOTE: Because `OEEDGER8R_COMMAND` is not a CMake
		# executable, we need an explicit dependency on it in
		# order to cause files to be regenerated if the
		# oeedger8r is rebuilt.
		DEPENDS ${EDL_FILE} oeedger8r ${OE_BINDIR}/${OEEDGER8R_COMMAND}
		COMMAND ${OE_BINDIR}/${OEEDGER8R_COMMAND} ${type_opt} ${headers_only} ${dir_opt} ${CMAKE_CURRENT_BINARY_DIR} ${EDL_FILE} --search-path ${in_path} ${edl_search_path}
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

