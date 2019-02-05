# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
    add_subdirectory(enc)
    add_subdirectory(libmalloc)
endif()

add_enclave_test(tests/malloc malloc_host malloc_enc)
