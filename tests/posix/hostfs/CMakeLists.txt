# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
    add_subdirectory(enc)
endif()

set(TMP_DIR "${CMAKE_CURRENT_BINARY_DIR}/tmp")

add_test(tests/hostfs1 cmake -E remove_directory "${TMP_DIR}")

add_enclave_test(tests/hostfs hostfs_host hostfs_enc "${TMP_DIR}")
