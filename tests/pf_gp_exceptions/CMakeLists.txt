# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_enclave_test(tests/pf_gp_exceptions pf_gp_exceptions_host
                 sgx_pf_gp_exceptions_enc_signed)
set_enclave_tests_properties(tests/pf_gp_exceptions PROPERTIES SKIP_RETURN_CODE
                             2)

add_enclave_test(tests/pf_gp_exceptions_unsigned pf_gp_exceptions_host
                 sgx_pf_gp_exceptions_enc_unsigned)
set_enclave_tests_properties(tests/pf_gp_exceptions_unsigned PROPERTIES
                             SKIP_RETURN_CODE 2)
