# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../switchless_one_tcs.edl)

add_custom_command(
  OUTPUT switchless_one_tcs_u.h switchless_one_tcs_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(switchless_one_tcs_host host.c switchless_one_tcs_u.c)

target_include_directories(switchless_one_tcs_host
                           PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(switchless_one_tcs_host oehost)
