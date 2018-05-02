# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (UNIX)
	add_subdirectory(enc)
endif()

# NOTE : Third parameter is the name of the signed enclave file which should 
# match with Linux build signed enclave file.
add_enclave_test(hostcalls hostcalls_host hostcalls_enc)
