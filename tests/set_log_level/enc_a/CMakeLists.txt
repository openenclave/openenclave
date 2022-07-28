# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../set_log_level_a.edl)

add_custom_command(
  OUTPUT set_log_level_a_t.h set_log_level_a_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  set_log_level_a_enc
  UUID
  c6d845e1-5fd6-4faf-9c73-d84e25d48fe0
  SOURCES
  enc.c
  ${CMAKE_CURRENT_BINARY_DIR}/set_log_level_a_t.c)

enclave_include_directories(set_log_level_a_enc PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})
