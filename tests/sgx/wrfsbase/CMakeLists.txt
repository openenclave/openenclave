# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_enclave_test(tests/sgx/wrfsbase wrfsbase_host sgx_wrfsbase_enc 0)
add_enclave_test(tests/sgx/wrfsbase_negative wrfsbase_host sgx_wrfsbase_enc 1)
