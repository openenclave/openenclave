# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(../socket_test.edl 
    host socket_test_u
    --edl-search-dir ../../../include
)

add_executable(socket_host
    host.c
    ${socket_test_u}
)

target_include_directories(socket_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(socket_host oehostapp)
