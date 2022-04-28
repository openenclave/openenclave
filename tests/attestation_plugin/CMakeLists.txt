# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_enclave_test(
  tests/attestation_plugin_mbedtls plugin_host plugin_mbedtls_enc
  ${CMAKE_CURRENT_SOURCE_DIR}/data/evidence
  ${CMAKE_CURRENT_SOURCE_DIR}/data/endorsements)
set_enclave_tests_properties(tests/attestation_plugin_mbedtls PROPERTIES
                             SKIP_RETURN_CODE 2)

if (BUILD_OPENSSL)
  add_enclave_test(
    tests/attestation_plugin_openssl plugin_host plugin_openssl_enc
    ${CMAKE_CURRENT_SOURCE_DIR}/data/evidence.txt
    ${CMAKE_CURRENT_SOURCE_DIR}/data/endorsements.txt)
  set_enclave_tests_properties(tests/attestation_plugin_openssl PROPERTIES
                               SKIP_RETURN_CODE 2)
endif ()
