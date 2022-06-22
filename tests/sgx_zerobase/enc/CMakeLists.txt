# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../sgx_zerobase.edl)

add_custom_command(
  OUTPUT sgx_zerobase_t.h sgx_zerobase_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(TARGET sgx_zerobase_macro_only_enc SOURCES enc.cpp props.cpp
            ${CMAKE_CURRENT_BINARY_DIR}/sgx_zerobase_t.c)

enclave_include_directories(
  sgx_zerobase_macro_only_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  sgx_zerobase_conf_only_enc
  SOURCES
  enc.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/sgx_zerobase_t.c
  CONFIG
  enable_zerobase.conf)

enclave_include_directories(
  sgx_zerobase_conf_only_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  sgx_zerobase_macro_disable_conf_enable_enc
  SOURCES
  enc.cpp
  props_sgx1.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/sgx_zerobase_t.c
  CONFIG
  enable_zerobase.conf)

enclave_include_directories(
  sgx_zerobase_macro_disable_conf_enable_enc PRIVATE
  ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  sgx_zerobase_macro_enable_conf_disable_enc
  SOURCES
  enc.cpp
  props.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/sgx_zerobase_t.c
  CONFIG
  disable_zerobase.conf)

enclave_include_directories(
  sgx_zerobase_macro_enable_conf_disable_enc PRIVATE
  ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR})
