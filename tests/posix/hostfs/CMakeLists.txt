# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
    add_subdirectory(enc)
endif()

set(TMP_DIR "${CMAKE_CURRENT_BINARY_DIR}/tmp")

if (UNIX)
add_test(tests/hostfs1 /bin/rm -rf "${TMP_DIR}")
else ()
add_test(tests/hostfs1 powershell.exe -Command " (rm -recurse -force ${TMP_DIR} ) >$null")
endif ()

add_enclave_test(tests/hostfs hostfs_host hostfs_enc "${TMP_DIR}")
