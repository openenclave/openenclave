# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
    add_subdirectory(enc)
endif()

add_enclave_test(tests/bigmalloc bigmalloc_host bigmalloc_enc_signed)
set_tests_properties(tests/bigmalloc PROPERTIES SKIP_RETURN_CODE 2)
