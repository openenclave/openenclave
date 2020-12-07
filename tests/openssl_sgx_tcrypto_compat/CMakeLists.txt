# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(OPENSSL_DIR ${PROJECT_SOURCE_DIR}/3rdparty/openssl/openssl)
add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_enclave_test(
  tests/openssl_sgx_tcrypto_compat_digest openssl_sgx_tcrypto_compat_host
  openssl_sgx_tcrypto_compat_enc TEST_GROUP_DIGEST)
