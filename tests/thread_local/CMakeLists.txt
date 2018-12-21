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

# Test enclaves with exported thread-locals.
add_enclave_test(tests/thread_local_exported
    thread_local_host 
	thread_local_enc_exported
	--exported-thread-locals)
