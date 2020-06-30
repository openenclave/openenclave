# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../pingpong.edl)

add_custom_command(
  OUTPUT pingpong_t.h pingpong_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  pingpong_enc
  UUID
  0a6cbbd3-160a-4c86-9d9d-c9cf1956be16
  SOURCES
  enc.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/pingpong_t.c)
enclave_include_directories(pingpong_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(pingpong_enc oelibc)
