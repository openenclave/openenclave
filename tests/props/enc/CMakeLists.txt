# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../props.edl)

add_custom_command(
  OUTPUT props_t.h props_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND edger8r --trusted ${EDL_FILE} --search-path
          ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  props_enc
  UUID
  3c1786e3-568f-4185-9ffa-1f198c98393e
  CONFIG
  sign.conf
  SOURCES
  enc.c
  props.c
  ${CMAKE_CURRENT_BINARY_DIR}/props_t.c)
add_enclave(
  TARGET
  props_enc_unsigned
  UUID
  14ade1b6-900b-4b5a-9b90-f115254e0293
  SOURCES
  enc.c
  props.c
  ${CMAKE_CURRENT_BINARY_DIR}/props_t.c)

enclave_include_directories(props_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
enclave_include_directories(props_enc_unsigned PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})

enclave_link_libraries(props_enc oelibc)
enclave_link_libraries(props_enc_unsigned oelibc)
