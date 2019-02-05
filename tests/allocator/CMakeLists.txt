# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
    add_subdirectory(enc)
    add_subdirectory(allocator)
endif()

add_enclave_test(tests/allocator allocator_host allocator_enc)
