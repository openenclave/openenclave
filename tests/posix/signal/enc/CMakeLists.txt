# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../signal_test.edl
    enclave signal_test_t
    --edl-search-dir ../../../include
)

add_enclave(
    TARGET signal_test_enc
    SOURCES enc.c ${signal_test_t}
)

target_include_directories(signal_test_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(signal_test_enc oelibc)
