# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../ocall_create.edl)

add_custom_command(
  OUTPUT ocall_create_t.h ocall_create_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  ocall_create_enc
  UUID
  1b74ddb4-9c9c-47d7-b34c-56e58ab1df6f
  SOURCES
  enc.c
  ${CMAKE_CURRENT_BINARY_DIR}/ocall_create_t.c)

enclave_include_directories(ocall_create_enc PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(ocall_create_enc oelibc)
