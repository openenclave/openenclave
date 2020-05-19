# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../switchless_threads.edl)

add_custom_command(
  OUTPUT switchless_threads_u.h switchless_threads_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND edger8r --untrusted ${EDL_FILE} --search-path
          ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(switchless_threads_host host.c switchless_threads_u.c)

target_include_directories(switchless_threads_host
                           PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(switchless_threads_host oehost)
