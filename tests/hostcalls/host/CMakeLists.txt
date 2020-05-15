# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../hostcalls.edl)

add_custom_command(
  OUTPUT hostcalls_u.h hostcalls_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND edger8r --untrusted ${EDL_FILE} --search-path
          ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(hostcalls_host host.cpp hostcalls_u.c)

target_include_directories(hostcalls_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                                                  ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(hostcalls_host oehost)
