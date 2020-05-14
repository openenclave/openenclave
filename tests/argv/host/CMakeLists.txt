# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../argv.edl)

add_custom_command(
  OUTPUT argv_u.h argv_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND edger8r --untrusted ${EDL_FILE} --search-path
          ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(argv_host host.c argv_u.c)

target_include_directories(argv_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(argv_host oehost)
