# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../ocall.edl)

add_custom_command(
  OUTPUT ocall_t.h ocall_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  ocall_enc
  UUID
  f39f25d8-266d-47ad-b9d3-77fb62100d14
  SOURCES
  enc.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/ocall_t.c)

enclave_include_directories(ocall_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

enclave_link_libraries(ocall_enc oelibcxx)
