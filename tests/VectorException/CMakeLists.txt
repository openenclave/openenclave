# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (UNIX)
	add_subdirectory(enc)
endif()

add_enclave_test(tests/VectorException VectorException_host VectorException_enc)
set_tests_properties(tests/VectorException PROPERTIES SKIP_RETURN_CODE 2)
