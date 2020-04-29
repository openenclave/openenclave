# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
    add_subdirectory(enc)
endif()

set(TMP_DIR "${CMAKE_CURRENT_BINARY_DIR}/tmp")

add_enclave_test(tests/fs
    fs_host
    fs_enc
    "${PROJECT_SOURCE_DIR}"
    "${TMP_DIR}")

set_enclave_tests_properties(tests/fs PROPERTIES SKIP_RETURN_CODE 2)
