# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(data)
add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

add_enclave_test(tests/crypto_crls_cert_chains crypto-extra_host
                 crypto-extra_enc)
