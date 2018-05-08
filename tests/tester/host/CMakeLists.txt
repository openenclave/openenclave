# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(oeidl_file)
oeidl_file(../tester.idl host gen)

add_executable(tester_host host.cpp ${gen})

target_include_directories(tester_host PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(tester_host oehostapp)
