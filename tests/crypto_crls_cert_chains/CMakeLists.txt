# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(data)

if (BUILD_ENCLAVES)
    add_subdirectory(enc)
endif()

# Disable test on Windows until host crypto dependencies are implemented
if (UNIX)
    add_subdirectory(host)
    add_enclave_test(tests/crypto_crls_cert_chains crypto-extra_host crypto-extra_enc)
endif()
