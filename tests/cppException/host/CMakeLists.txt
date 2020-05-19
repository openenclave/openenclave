# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../cppException.edl)

add_custom_command(
  OUTPUT cppException_u.h cppException_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND edger8r --untrusted ${EDL_FILE} --search-path
          ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(cppException_host host.cpp cppException_u.c)

target_include_directories(
  cppException_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                            ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(cppException_host oehost)
