# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_enclave_test(tests/attestation_plugin_cert tls_cert_host tls_cert_enc)
set_enclave_tests_properties(tests/attestation_plugin_cert PROPERTIES
                             SKIP_RETURN_CODE 2)
