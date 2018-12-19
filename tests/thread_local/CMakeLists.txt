# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (UNIX)
	add_subdirectory(enc)
endif()

# Test enclaves without exported thread-locals.
add_enclave_test(tests/thread_local 
     thread_local_host 
     thread_local_enc)

set_tests_properties(tests/thread_local PROPERTIES SKIP_RETURN_CODE 2)

# Test enclaves with exported thread-locals.
add_enclave_test(tests/thread_local_exported
    thread_local_host 
	thread_local_enc_exported
	--exported-thread-locals)

set_tests_properties(tests/thread_local_exported PROPERTIES SKIP_RETURN_CODE 2)	
