# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeedl_file)

oeedl_file(../libc.edl host gen)

add_executable(libc_host host.cpp)

add_executable(libc_host host.cpp ${gen})

target_include_directories(libc_host PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(libc_host oehostapp)
