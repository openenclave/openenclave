# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(../socketpair_test.edl 
    host socketpair_test_u
    --edl-search-dir ../../../include
)

add_executable(socketpair_host
    host.c
    ${socketpair_test_u}
)

target_include_directories(socketpair_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(socketpair_host oehostapp)
