# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../thread_local_large.edl)

add_custom_command(
  OUTPUT thread_local_large_t.h thread_local_large_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  thread_local_large_enc
  UUID
  5bf1ee3d-0cf2-44f7-8120-6efb1de7c3ad
  CXX
  SOURCES
  enc.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/thread_local_large_t.c)

enclave_include_directories(thread_local_large_enc PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})
