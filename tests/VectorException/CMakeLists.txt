# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

if (ADD_WINDOWS_ENCLAVE_TESTS)
	add_subdirectory(host)
    include(add_wnd_enclave_tests)
    add_wnd_enclave_tests(VectorException VectorExceptionHost VectorExceptionEnc.signed.so) #TODO : set_tests_properties(tests/VectorException PROPERTIES SKIP_RETURN_CODE 2)
else()
add_subdirectory(enc)
add_subdirectory(host)

add_test(tests/VectorException host/VectorExceptionHost ./enc/VectorExceptionEnc.signed.so)
set_tests_properties(tests/VectorException PROPERTIES SKIP_RETURN_CODE 2)
endif()