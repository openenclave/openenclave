# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../mman.edl)

add_custom_command(
  OUTPUT mman_t.h mman_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  mman_enc
  UUID
  71b0822f-42a3-4543-a97c-ca491f76b82c
  SOURCES
  enc.c
  ${CMAKE_CURRENT_BINARY_DIR}/mman_t.c)

enclave_include_directories(mman_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(mman_enc oelibc)
