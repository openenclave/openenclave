# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set (EDL_FILE ../resolver_test.edl)

add_custom_command(
    OUTPUT resolver_test_t.h resolver_test_t.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r --trusted ${EDL_FILE} --search-path ${CMAKE_CURRENT_SOURCE_DIR}
            --search-path ${CMAKE_CURRENT_SOURCE_DIR}/../../../include)

add_enclave(
    TARGET resolver_enc
    SOURCES enc.c resolver_test_t.c
)

target_include_directories(resolver_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
maybe_build_using_clangw(resolver_enc)

target_link_libraries(resolver_enc oelibc oehostresolver)
