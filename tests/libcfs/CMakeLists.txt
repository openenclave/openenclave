# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
    add_subdirectory(enc)
endif()

set(TMP_DIR "${CMAKE_BINARY_DIR}/tests/libcfs/tmp")

add_test(tests/libcfs1 /bin/rm -rf "${TMP_DIR}")

add_enclave_test(tests/libcfs
    libcfs_host
    libcfs_enc
    "${TMP_DIR}")
