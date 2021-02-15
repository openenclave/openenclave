# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../config_id.edl)

add_custom_command(
  OUTPUT config_id_t.h config_id_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  config_id_enc
  UUID
  25419627-14f6-4625-9329-cf5f10a57fea
  SOURCES
  enc.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/config_id_t.c)

enclave_include_directories(config_id_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                            ${CMAKE_CURRENT_SOURCE_DIR})
