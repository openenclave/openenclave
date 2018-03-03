# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeidl_file)
oeidl_file(../pingpong.idl host gen)

add_executable(pingponghost host.cpp ${gen})

target_include_directories(pingponghost PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(pingponghost oehostapp)
