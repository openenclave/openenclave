# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_subdirectory(host)

# Disable because this test would fail with code coverage
# Output: ***Exception: SegFault
if (NOT CODE_COVERAGE)
  add_enclave_test(tests/crypto/enclave_mbedtls cryptohost crypto_mbedtls_enc
                   ${CMAKE_CURRENT_BINARY_DIR})
endif ()

set(TEST_DIR ${CMAKE_CURRENT_BINARY_DIR})

if (WIN32)
  string(REPLACE "C:/" "" TEST_DIR "${TEST_DIR}")
endif ()

if (BUILD_OPENSSL)
  add_enclave_test(tests/crypto/enclave_openssl cryptohost crypto_openssl_enc
                   ${TEST_DIR})

  add_enclave_test(tests/crypto/enclave_openssl_3 cryptohost
                   crypto_openssl_3_enc ${TEST_DIR})
endif ()
