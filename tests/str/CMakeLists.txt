# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_executable(str main.c)
target_link_libraries(str oehost)
target_compile_options(str PRIVATE -Wconversion -Wpointer-arith)

add_test(NAME tests/str COMMAND str WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
