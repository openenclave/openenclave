# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../create_errors.edl)

add_custom_command(
  OUTPUT create_errors_u.h create_errors_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND edger8r --untrusted ${EDL_FILE} --search-path
          ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(create_errors_host host.c create_errors_u.c)

target_include_directories(
  create_errors_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                             ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(create_errors_host oehost)
