# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../backtrace.edl)

add_custom_command(
  OUTPUT backtrace_u.h backtrace_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND edger8r --untrusted ${EDL_FILE} --search-path
          ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(backtrace_host host.cpp backtrace_u.c)

target_include_directories(backtrace_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                                                  ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(backtrace_host oehost)
