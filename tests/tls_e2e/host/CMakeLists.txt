# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../tls_e2e.edl)

add_custom_command(
  OUTPUT tls_e2e_u.h tls_e2e_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND edger8r --untrusted ${EDL_FILE} --search-path
          ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(tls_e2e_host host.cpp tls_e2e_u.c)

target_include_directories(tls_e2e_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                                                ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(tls_e2e_host oehost)
