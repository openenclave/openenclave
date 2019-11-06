# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

oeedl_file(../pingpong.edl host gen)

add_executable(pingpong_host host.cpp ${gen})

target_include_directories(pingpong_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(pingpong_host oehostapp)
