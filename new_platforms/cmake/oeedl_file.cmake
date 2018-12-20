# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

macro(edl_file TOOL EDL_FILE TYPE OUT_FILES_VAR OUT_C_FILES_VAR OUT_H_FILES_VAR EDL_SEARCH_PATHS)
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

	if("${EDL_SEARCH_PATHS}" STREQUAL "")
		set(edl_search_path ${in_path})
	else()
		set(edl_search_path ${in_path} ${EDL_SEARCH_PATHS})
		if(UNIX)
			string(REPLACE ";" ":" edl_search_path "${edl_search_path}")
		endif()
		set(edl_search_path "\"${edl_search_path}\"")
	endif()

	set(h_file ${CMAKE_CURRENT_BINARY_DIR}/${idl_base}_${type_id}.h)

	if(WIN32)
		if("${TOOL}" STREQUAL "SGX")
			set(TOOL_COMMAND ${SGX_SDK_EDGER8R_TOOL})
		elseif("${TOOL}" STREQUAL "OE")
			set(TOOL_COMMAND ${OEEDGER8R_PATH})
		else()
			message(FATAL_ERROR "Invalid generator tool ${TOOL} - must be \"SGX\" or \"OE\"")
		endif()
	elseif(UNIX)
		if("${TOOL}" STREQUAL "SGX")
			message(FATAL_ERROR "Intel's generator tool is not supported on Linux")
		elseif("${TOOL}" STREQUAL "OE")
			set(TOOL_COMMAND ${OEEDGER8R_PATH})
		else()
			message(FATAL_ERROR "Invalid generator tool ${TOOL} - must be \"OE\" on Linux")
		endif()
	endif()

	add_custom_command(
		OUTPUT ${h_file} ${c_file}
		# NOTE: Because `TOOL_COMMAND` is not a CMake
		# executable, we need an explicit dependency on it in
		# order to cause files to be regenerated if the
		# edger8r tool is rebuilt.
		COMMAND ${TOOL_COMMAND} ${type_opt} ${headers_only} ${dir_opt} ${CMAKE_CURRENT_BINARY_DIR} ${EDL_FILE} --search-path "${edl_search_path}"
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

	list(APPEND ${OUT_C_FILES_VAR} ${c_file})
	set(${OUT_C_FILES_VAR} ${${OUT_C_FILES_VAR}} PARENT_SCOPE)

	list(APPEND ${OUT_H_FILES_VAR} ${h_file})
	set(${OUT_H_FILES_VAR} ${${OUT_H_FILES_VAR}} PARENT_SCOPE)
endmacro(edl_file)

function(oeedl_file EDL_FILE TYPE OUT_FILES_VAR OUT_C_FILES_VAR OUT_H_FILES_VAR)
	edl_file(OE ${EDL_FILE} ${TYPE} ${OUT_FILES_VAR} ${OUT_C_FILES_VAR} ${OUT_H_FILES_VAR} "${ARGV5}")
endfunction(oeedl_file)

function(sgxedl_file EDL_FILE TYPE OUT_FILES_VAR OUT_C_FILES_VAR OUT_H_FILES_VAR)
	edl_file(SGX ${EDL_FILE} ${TYPE} ${OUT_FILES_VAR} ${OUT_C_FILES_VAR} ${OUT_H_FILES_VAR} "${ARGV5}")
endfunction(sgxedl_file)
