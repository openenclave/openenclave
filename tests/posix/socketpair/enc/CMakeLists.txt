# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../socketpair_test.edl 
    enclave socketpair_test_t
    --edl-search-dir ../../../include
)

add_enclave(TARGET socketpair_enc SOURCES enc.c ${socketpair_test_t})

target_include_directories(socketpair_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(socketpair_enc oelibc oehostsock)
