# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
    add_subdirectory(enc)
endif()

add_enclave_test(tests/attestation_cert_api tls_host tls_enc)
set_tests_properties(tests/attestation_cert_api PROPERTIES SKIP_RETURN_CODE 2)
