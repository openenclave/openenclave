# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../VectorException.edl)

add_custom_command(
  OUTPUT VectorException_u.h VectorException_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND edger8r --untrusted ${EDL_FILE} --search-path
          ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(VectorException_host host.c VectorException_u.c)

target_link_libraries(VectorException_host oehost)

target_include_directories(VectorException_host
                           PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
