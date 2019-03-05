# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(../epoll_test.edl
    host epoll_test_u
    --edl-search-dir ../../../include
)

add_executable(polling_test_host
    host.c
    ${epoll_test_u}
)

target_link_libraries(polling_test_host oeepoll_host)
target_include_directories(polling_test_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(polling_test_host oehostapp)
