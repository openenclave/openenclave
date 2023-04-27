# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_enclave_test(tests/attestation_plugin_mbedtls plugin_host
                 plugin_mbedtls_enc)
set_enclave_tests_properties(tests/attestation_plugin_mbedtls PROPERTIES
                             SKIP_RETURN_CODE 2)

if (BUILD_OPENSSL)
  add_enclave_test(tests/attestation_plugin_openssl plugin_host
                   plugin_openssl_enc)
  set_enclave_tests_properties(tests/attestation_plugin_openssl PROPERTIES
                               SKIP_RETURN_CODE 2)

  add_enclave_test(tests/attestation_plugin_openssl_3 plugin_host
                   plugin_openssl_3_enc)
  set_enclave_tests_properties(tests/attestation_plugin_openssl_3 PROPERTIES
                               SKIP_RETURN_CODE 2)
endif ()
