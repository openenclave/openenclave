# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_custom_command(
  OUTPUT tls_server_u.h tls_server_u.c tls_server_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/server/tls_server.edl
  COMMAND openenclave::oeedger8r --untrusted
          ${CMAKE_SOURCE_DIR}/server/tls_server.edl)

add_executable(tls_server_host host.cpp
                               ${CMAKE_CURRENT_BINARY_DIR}/tls_server_u.c)

target_include_directories(tls_server_host PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
                                                   ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(tls_server_host openenclave::oehost)
