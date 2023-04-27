# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_subdirectory(host)

# Disable because this test would fail with code coverage
# Output: ***Exception: SegFault
if (NOT CODE_COVERAGE)
  add_enclave_test(tests/crypto/enclave_mbedtls cryptohost crypto_mbedtls_enc)
endif ()

if (BUILD_OPENSSL)
  add_enclave_test(tests/crypto/enclave_openssl cryptohost crypto_openssl_enc)

  add_enclave_test(tests/crypto/enclave_openssl_3 cryptohost
                   crypto_openssl_3_enc)
endif ()
