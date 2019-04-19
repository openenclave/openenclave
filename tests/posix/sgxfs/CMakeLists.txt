# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
    add_subdirectory(enc)
endif()

set(TMP_DIR "${CMAKE_CURRENT_BINARY_DIR}/tmp")

add_test(tests/sgxfs1 /bin/rm -rf "${TMP_DIR}")

add_enclave_test(tests/sgxfs sgxfs_host sgxfs_enc "${TMP_DIR}")
