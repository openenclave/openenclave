# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_enclave_test(tests/sgx_zerobase_macro_only sgx_zerobase_host
                 sgx_zerobase_macro_only_enc)
set_enclave_tests_properties(tests/sgx_zerobase_macro_only 
                               PROPERTIES SKIP_RETURN_CODE 2)
                             

# Tests 0-base enclave creation when OE_SET_ENCLAVE_SGX*() macro is not
# used and only oesign configuration file is used to set properties.
add_enclave_test(tests/sgx_zerobase_conf_only sgx_zerobase_host
                 sgx_zerobase_conf_only_enc_signed)
set_enclave_tests_properties(tests/sgx_zerobase_conf_only 
                               PROPERTIES SKIP_RETURN_CODE 2)
                               
# Tests 0-base enclave creation when OE_SET_ENCLAVE_SGX*() macro disables
# 0-base enclave creation and oesign configuration file enables 0-base enclave creation.
add_enclave_test(
  tests/sgx_zerobase_prop_macro_disable_conf_enable sgx_zerobase_host
  sgx_zerobase_macro_disable_conf_enable_enc_signed)
set_enclave_tests_properties(tests/sgx_zerobase_prop_macro_disable_conf_enable
                               PROPERTIES SKIP_RETURN_CODE 2)
                               
# Tests 0-base enclave creation when OE_SET_ENCLAVE_SGX*() macro enables
# 0-base enclave creation but oesign configuration file disables 0-base enclave creation.
add_enclave_test(tests/sgx_zerobase_macro_enable_conf_disable sgx_zerobase_host
                 sgx_zerobase_macro_enable_conf_disable_enc_signed)
set_enclave_tests_properties(tests/sgx_zerobase_macro_enable_conf_disable
                               PROPERTIES SKIP_RETURN_CODE 2)
                               
