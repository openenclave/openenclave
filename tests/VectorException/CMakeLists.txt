# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (UNIX)
	add_subdirectory(enc)
endif()

# NOTE : Third parameter is the name of the signed enclave file which should 
# match with Linux build signed enclave file.
add_enclave_test(VectorException VectorException_host VectorException_enc 2)	# last parameter is to set SKIP_RETURN_CODE properties value.

#set_tests_properties(tests/VectorException PROPERTIES SKIP_RETURN_CODE 2)
