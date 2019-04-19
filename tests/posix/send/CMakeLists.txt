# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
    add_subdirectory(enc1)
    add_subdirectory(enc2)
endif()

add_enclave_test(tests/libcsock1 libcsock_host libcsock_enc1)
add_enclave_test(tests/libcsock2 libcsock_host libcsock_enc2)
