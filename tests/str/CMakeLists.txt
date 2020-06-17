# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_executable(str main.c)
target_link_libraries(str oehost)

add_test(
  NAME tests/str
  COMMAND str
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
