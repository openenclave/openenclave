# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(logging main.c)
target_link_libraries(logging oehost)

add_test(NAME tests/logging COMMAND logging ${CMAKE_CURRENT_BINARY_DIR}/out.log WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
