# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
	add_subdirectory(enc)
endif()

add_enclave_test(tests/stdcxx stdcxx_host stdcxx_enc OE_OK)

# Some expection test will fail in simulation mode, due to the failure of
# isolation of exception in enclave then host process will be terminated.

add_enclave_test(tests/global_init_exception stdcxx_host global_init_exception_enc OE_ENCLAVE_ABORTING)
set_enclave_tests_properties(tests/global_init_exception PROPERTIES SKIP_RETURN_CODE 2)
