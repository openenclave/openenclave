# Copyright (c) Open Enclave SDK contributors.
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
maybe_build_using_clangw(resolver_enc)

target_link_libraries(resolver_enc oelibc oehostresolver)
