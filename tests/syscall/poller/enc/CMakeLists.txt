# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../poller.edl)

add_custom_command(
  OUTPUT poller_t.h poller_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  poller_enc
  SOURCES
  enc.cpp
  ../client.cpp
  ../server.cpp
  ../poller.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/poller_t.c)

enclave_link_libraries(poller_enc oelibcxx oeenclave oehostepoll oehostsock)
