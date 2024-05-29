# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_enclave_test(tests/symcrypt_provider symcrypt_provider_host
                 sgx_symcrypt_provider_enc)

add_enclave_test(
  tests/symcrypt_provider_no_entropy symcrypt_provider_no_entropy_host
  sgx_symcrypt_provider_no_entropy_enc)
