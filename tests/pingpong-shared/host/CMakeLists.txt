# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

oeedl_file(../pingpong.edl host gen)

add_library(pingpong-shared-lib SHARED host.cpp ${gen})

target_include_directories(pingpong-shared-lib PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(pingpong-shared-lib oehostapp)

add_executable(pingpong-shared_host main.cpp)
target_link_libraries(pingpong-shared_host pingpong-shared-lib)

