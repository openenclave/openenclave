# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

oeedl_file(../thread.edl host gen)

add_executable(thread_host host.cpp rwlocks_test_host.cpp ${gen})

target_include_directories(thread_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURENT_SOURCE_DIR})

target_link_libraries(thread_host oehostapp)
