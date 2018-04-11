# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
# Helper function to obtain name for a test-case. Given a filename, chop
# extension, dir-prefix, and replace special chars.
#
# Usage:
#
#       get_testcase_name(<filename> <namevar>)
#
# Arguments:
# filename - filename containing the test
# namevar - variable to receive the testcase name
#
function(get_testcase_name FILENAME NAMEVAR)
        string(REGEX REPLACE "\.c(pp)?$" "" n ${FILENAME})
        string(REGEX REPLACE "^\.\./\.\./3rdparty/(mbedtls/mbedtls/programs/test/|libcxx/libcxx/test/|musl/libc-test/src/)" "" n ${n})
        string(REGEX REPLACE "[/=]" "_" n ${n})
        string(REGEX REPLACE "[\!]" "-" n ${n})
	set(${NAMEVAR} ${n} PARENT_SCOPE)
endfunction(get_testcase_name)
