# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc)
endif ()

set(TMP_DIR "${CMAKE_CURRENT_BINARY_DIR}/tmp")

add_test(tests/dup1 cmake -E remove_directory "${TMP_DIR}")

add_enclave_test(tests/dup2 dup_host dup_enc "${TMP_DIR}")
