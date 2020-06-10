# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../getenclave.edl)

add_custom_command(
  OUTPUT getenclave_t.h getenclave_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  getenclave_enc
  UUID
  73c0418e-4d0f-49ef-905f-008f144eb297
  SOURCES
  enc.c
  ${CMAKE_CURRENT_BINARY_DIR}/getenclave_t.c)

enclave_include_directories(getenclave_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(getenclave_enc oelibc)
