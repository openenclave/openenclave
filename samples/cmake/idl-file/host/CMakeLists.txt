# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeidl_file)
oeidl_file(../file.idl host gen)

add_executable(samples-filehost host.cpp ${gen})

target_include_directories(samples-filehost PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(samples-filehost oeidl oehostapp)
