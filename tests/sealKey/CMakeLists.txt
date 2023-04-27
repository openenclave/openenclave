# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_enclave_test(tests/sealKey_mbedtls sealKey_host sealKey_mbedtls_enc)
set_enclave_tests_properties(tests/sealKey_mbedtls PROPERTIES SKIP_RETURN_CODE
                             2)

if (BUILD_OPENSSL)
  add_enclave_test(tests/sealKey_openssl sealKey_host sealKey_openssl_enc)
  set_enclave_tests_properties(tests/sealKey_openssl PROPERTIES
                               SKIP_RETURN_CODE 2)

  add_enclave_test(tests/sealKey_openssl_3 sealKey_host sealKey_openssl_3_enc)
  set_enclave_tests_properties(tests/sealKey_openssl_3 PROPERTIES
                               SKIP_RETURN_CODE 2)
endif ()
