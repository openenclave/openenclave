# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_enclave_test(tests/symcrypt_engine symcrypt_engine_host
                 sgx_symcrypt_engine_enc)

add_enclave_test(
  tests/symcrypt_engine_no_entropy symcrypt_engine_no_entropy_host
  sgx_symcrypt_engine_no_entropy_enc)
