# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (UNIX)
	add_subdirectory(enc)
endif()

add_enclave_test(tests/report ./host report_host ./enc report_enc)
set_tests_properties(tests/report PROPERTIES SKIP_RETURN_CODE 2)
