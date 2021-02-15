# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../poller.edl)

add_custom_command(
  OUTPUT poller_u.h poller_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(poller_host host.cpp ../client.cpp ../server.cpp ../poller.cpp
                           poller_u.c)

target_include_directories(poller_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(poller_host oehost)
