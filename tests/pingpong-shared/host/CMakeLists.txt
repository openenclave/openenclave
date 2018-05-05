# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeidl_file)
oeidl_file(../pingpong.idl host gen)

add_library(pingpong-shared-lib SHARED host.cpp ${gen})

target_include_directories(pingpong-shared-lib PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(pingpong-shared-lib oehostapp)

add_executable(pingpong-shared-host main.cpp)
target_link_libraries(pingpong-shared-host pingpong-shared-lib)

