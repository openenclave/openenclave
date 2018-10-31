# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)
oeedl_file(../pingpong.edl host gen)

add_library(pingpong-shared-lib SHARED host.cpp ${gen})

target_include_directories(pingpong-shared-lib PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(pingpong-shared-lib oehostapp)

add_executable(pingpong-shared_host main.cpp)
target_link_libraries(pingpong-shared_host pingpong-shared-lib)
target_compile_options(pingpong-shared_host PRIVATE -Wconversion -Wpointer-arith)

