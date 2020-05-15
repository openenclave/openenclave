# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../getenclave.edl)

add_custom_command(
  OUTPUT getenclave_u.h getenclave_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND edger8r --untrusted ${EDL_FILE} --search-path
          ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(getenclave_host host.c getenclave_u.c)
target_include_directories(getenclave_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(getenclave_host oehost)
