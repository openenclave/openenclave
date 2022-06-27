# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_enclave_test(tests/sgx/extra_data extra_data_host sgx_extra_data_enc
                 nozerobase)

# Only test with zero-based feature on Linux
if (UNIX)
  add_enclave_test(tests/sgx/extra_data_with_zerobase extra_data_host
                   sgx_extra_data_zerobase_enc zerobase)
  set_enclave_tests_properties(tests/sgx/extra_data_with_zerobase PROPERTIES
                               SKIP_RETURN_CODE 2)
endif ()
