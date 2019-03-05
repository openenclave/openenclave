# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../epoll_test.edl
    enclave epoll_test_t
    --edl-search-dir ../../../include
)

add_enclave(
    TARGET polling_test_enc
    SOURCES enc.c ${epoll_test_t}
)

target_include_directories(polling_test_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(polling_test_enc oe_epoll_enc oelibc)
