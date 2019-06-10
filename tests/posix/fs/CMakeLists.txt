# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
    add_subdirectory(enc)
endif()

set(TMP_DIR "${CMAKE_CURRENT_BINARY_DIR}/tmp")

add_test(tests/fs1 cmake -E remove_directory "${TMP_DIR}")

add_enclave_test(tests/fs2
    fs_host
    fs_enc
    "${PROJECT_SOURCE_DIR}"
    "${TMP_DIR}")

maybe_build_using_clangw(fs_enc)

set_tests_properties(tests/fs2 PROPERTIES SKIP_RETURN_CODE 2)
