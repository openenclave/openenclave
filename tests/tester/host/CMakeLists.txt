# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeidl_file)
oeidl_file(../tester.idl host gen)

add_executable(testerhost host.cpp ${gen})

target_include_directories(testerhost PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(testerhost oehostapp)
