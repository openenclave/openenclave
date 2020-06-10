# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../sendmsg.edl)

add_custom_command(
  OUTPUT sendmsg_t.h sendmsg_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

##==============================================================================
##
## sendmsg_enc:
##
##==============================================================================

add_enclave(
  TARGET
  sendmsg_enc
  SOURCES
  enc.c
  ../client.c
  ../server.c
  ${CMAKE_CURRENT_BINARY_DIR}/sendmsg_t.c)

enclave_link_libraries(sendmsg_enc oelibc oeenclave oehostsock)
