# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../sendmsg.edl)

add_custom_command(
  OUTPUT sendmsg_u.h sendmsg_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(sendmsg_host host.c ../client.c ../server.c sendmsg_u.c)

target_include_directories(sendmsg_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(sendmsg_host oehost)
