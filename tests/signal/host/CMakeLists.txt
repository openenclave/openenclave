# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(../signal_test.edl
    host signal_test_u
    --edl-search-dir ../../../include
)

add_executable(signal_test_host
    host.c
    ${signal_test_u}
)

target_include_directories(signal_test_host
    PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(signal_test_host oehostapp)
