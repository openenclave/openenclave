# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../create_errors.edl)

add_custom_command(
  OUTPUT create_errors_t.h create_errors_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  create_errors_enc
  UUID
  1083bbac-751e-4d26-ada6-c254bbfbe653
  SOURCES
  enc.c
  ${CMAKE_CURRENT_BINARY_DIR}/create_errors_t.c)

enclave_include_directories(
  create_errors_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR})

enclave_link_libraries(create_errors_enc oelibc)
