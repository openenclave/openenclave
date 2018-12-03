# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (UNIX)
	add_subdirectory(enc)
endif()

add_enclave_test(tests/thread_local 
    ./host thread_local_host 
	./enc thread_local_enc)

set_tests_properties(tests/thread_local PROPERTIES SKIP_RETURN_CODE 2)
