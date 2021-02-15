# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_subdirectory(host)
add_enclave_test(tests/crypto/enclave_mbedtls cryptohost crypto_mbedtls_enc)

if (BUILD_OPENSSL)
  add_enclave_test(tests/crypto/enclave_openssl cryptohost crypto_openssl_enc)
endif ()
