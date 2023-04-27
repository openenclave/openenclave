# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

if (BUILD_ENCLAVES)
  add_subdirectory(server_enc)
  add_subdirectory(client_enc)
endif ()
add_subdirectory(host)

add_enclave_test(tests/mbedtls_tls_e2e mbedtls_tls_e2e_host
                 mbedtls_tls_server_enc $<TARGET_FILE:mbedtls_tls_client_enc>)

set_enclave_tests_properties(tests/mbedtls_tls_e2e PROPERTIES SKIP_RETURN_CODE
                             2)

if (BUILD_OPENSSL)
  add_enclave_test(tests/openssl_tls_e2e openssl_tls_e2e_host
                   openssl_tls_server_enc $<TARGET_FILE:openssl_tls_client_enc>)
  set_enclave_tests_properties(tests/openssl_tls_e2e PROPERTIES
                               SKIP_RETURN_CODE 2)

  add_enclave_test(tests/openssl_3_tls_e2e openssl_tls_e2e_host
                   openssl_tls_server_enc $<TARGET_FILE:openssl_tls_client_enc>)
  set_enclave_tests_properties(tests/openssl_3_tls_e2e PROPERTIES
                               SKIP_RETURN_CODE 2)
endif ()
