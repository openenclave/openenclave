# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (UNIX)
	add_subdirectory(enc)
endif()

# NOTE : Third parameter is the name of the signed enclave file which should 
# match with Linux build signed enclave file.
add_enclave_test(report report_host report_enc)

#TODO : add support for below statement.
#set_tests_properties(tests/report PROPERTIES SKIP_RETURN_CODE 2)
