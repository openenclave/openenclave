# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (UNIX)
	add_subdirectory(enc)

	# note: this is Linux-specific
	add_test(NAME tests/print
		WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
		COMMAND sh -c OE_LOG_LEVEL=NONE "host/print_host ./enc/print_enc >testout.stdout 2>testout.stderr &&
			diff ${CMAKE_CURRENT_SOURCE_DIR}/printhost.stdout testout.stdout &&
			diff ${CMAKE_CURRENT_SOURCE_DIR}/printhost.stderr testout.stderr"
		)
else()

	add_enclave_test(tests/print print_host print_enc)

endif()
