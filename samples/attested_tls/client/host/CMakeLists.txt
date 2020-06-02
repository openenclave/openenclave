# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_custom_command(
  OUTPUT tls_client_u.h tls_client_u.c tls_client_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/client/tls_client.edl
  COMMAND
    openenclave::oeedger8r --untrusted
    ${CMAKE_SOURCE_DIR}/client/tls_client.edl --search-path ${OE_INCLUDEDIR}
    --search-path ${OE_INCLUDEDIR}/openenclave/edl/sgx)

add_executable(tls_client_host host.cpp
                               ${CMAKE_CURRENT_BINARY_DIR}/tls_client_u.c)

target_include_directories(tls_client_host PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
                                                   ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(tls_client_host openenclave::oehost)
