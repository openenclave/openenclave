# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_enclave_test(tests/sgx/td_state td_state_host sgx_td_state_enc)
set_enclave_tests_properties(tests/sgx/td_state PROPERTIES SKIP_RETURN_CODE 2)
