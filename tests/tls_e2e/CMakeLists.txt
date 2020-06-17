# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

if (BUILD_ENCLAVES)
  add_subdirectory(server_enc)
  add_subdirectory(client_enc)
endif ()
add_subdirectory(host)

set(TEST_NAME "tests/tls_e2e_host")
set(HOST_FILE "tls_e2e_host")
set(ENC_FILE "tls_server_enc")
set(ENC_FILE2 "tls_client_enc")

add_enclave_test(tests/tls_e2e tls_e2e_host tls_server_enc
                 $<TARGET_FILE:tls_client_enc>)

set_enclave_tests_properties(tests/tls_e2e PROPERTIES SKIP_RETURN_CODE 2)
