# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_executable(logging main.c)
target_link_libraries(logging oehost)

add_test(
  NAME tests/logging
  COMMAND logging
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
