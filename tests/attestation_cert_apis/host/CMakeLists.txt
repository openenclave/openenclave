# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include(add_dcap_client_target)

set(EDL_FILE ../tls.edl)

add_custom_command(
  OUTPUT tls_u.h tls_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(tls_host host.cpp tls_u.c)

target_include_directories(tls_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(tls_host oehost)

# On Windows, explicitly add the nuget dependencies for the DCAP client to the target executable
if (WIN32)
  add_dcap_client_target(tls_host_dcap_client)
  add_dependencies(tls_host tls_host_dcap_client)
endif ()
