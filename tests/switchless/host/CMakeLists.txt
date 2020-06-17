# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../switchless_test.edl)

add_custom_command(
  OUTPUT switchless_test_u.h switchless_test_u.c switchless_test_args.h
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(switchless_host host.c switchless_test_u.c)

target_include_directories(switchless_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(switchless_host oehost)
