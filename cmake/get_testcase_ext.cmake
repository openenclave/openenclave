# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
# Helper function to obtain name for a test-case. Given a filename, chop
# extension, dir-prefix, and replace special chars.
#
# Usage:
#
#       get_testcase_ext(<filename> <namevar>)
#
# Arguments:
# filename - filename containing the test
# namevar - variable to receive the testcase name
#
function(get_testcase_ext FILENAME EXTENSION)
	get_filename_component(F_EXT ${FILENAME} EXT)
	string(REGEX REPLACE "\\." "" F_EXT ${F_EXT})	
	string(TOLOWER ${F_EXT} F_EXT)
	string(REGEX REPLACE "x" "p" F_EXT ${F_EXT})	
	set(EXTENSION ${F_EXT} PARENT_SCOPE)
endfunction(get_testcase_ext)
