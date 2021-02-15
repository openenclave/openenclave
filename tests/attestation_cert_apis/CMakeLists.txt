# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_enclave_test(tests/attestation_cert_api_mbedtls tls_host tls_mbedtls_enc)
set_enclave_tests_properties(tests/attestation_cert_api_mbedtls PROPERTIES
                             SKIP_RETURN_CODE 2)

if (BUILD_OPENSSL)
  add_enclave_test(tests/attestation_cert_api_openssl tls_host tls_openssl_enc)
  set_enclave_tests_properties(tests/attestation_cert_api_openssl PROPERTIES
                               SKIP_RETURN_CODE 2)
endif ()
