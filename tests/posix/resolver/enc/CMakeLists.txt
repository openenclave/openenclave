# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../resolver_test.edl
    enclave resolver_test_t
    --edl-search-dir ../../../include
)

add_enclave(
    TARGET resolver_enc
    SOURCES enc.c ${resolver_test_t}
)

target_include_directories(resolver_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(resolver_enc oelibc oehostresolver)
