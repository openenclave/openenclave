# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

set(TMP_DIR "${CMAKE_CURRENT_BINARY_DIR}/tmp")

add_enclave_test(tests/hostfs hostfs_host hostfs_enc "${TMP_DIR}")
