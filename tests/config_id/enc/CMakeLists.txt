# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../config_id.edl)

add_custom_command(
  OUTPUT config_id_t.h config_id_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(TARGET config_id_kss_enc_unsigned SOURCES enc.c props_kss.c
            ${CMAKE_CURRENT_BINARY_DIR}/config_id_t.c)

enclave_include_directories(
  config_id_kss_enc_unsigned PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(TARGET config_id_enc_unsigned SOURCES enc.c props.c
            ${CMAKE_CURRENT_BINARY_DIR}/config_id_t.c)

enclave_include_directories(
  config_id_enc_unsigned PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  config_id_kss_enc
  CONFIG
  sign_kss.conf
  SOURCES
  enc.c
  props_kss.c
  ${CMAKE_CURRENT_BINARY_DIR}/config_id_t.c)

enclave_include_directories(
  config_id_kss_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  config_id_enc
  CONFIG
  sign.conf
  SOURCES
  enc.c
  props.c
  ${CMAKE_CURRENT_BINARY_DIR}/config_id_t.c)

enclave_include_directories(config_id_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                            ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  config_id_no_kss_conf_enc
  CONFIG
  sign.conf
  SOURCES
  enc.c
  props_kss.c
  ${CMAKE_CURRENT_BINARY_DIR}/config_id_t.c)

enclave_include_directories(
  config_id_no_kss_conf_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR})
