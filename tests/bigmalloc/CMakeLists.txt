# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
    add_subdirectory(enc)
endif()

add_enclave_test(tests/bigmalloc bigmalloc_host bigmalloc_enc_signed)
set_enclave_tests_properties(tests/bigmalloc PROPERTIES SKIP_RETURN_CODE 2)
