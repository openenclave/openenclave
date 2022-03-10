# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../pf_gp_exceptions.edl)

add_custom_command(
  OUTPUT pf_gp_exceptions_t.h pf_gp_exceptions_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  sgx_pf_gp_exceptions_enc
  CONFIG
  sign_pfgp.conf
  SOURCES
  enc.c
  props_pfgp.c
  ${CMAKE_CURRENT_BINARY_DIR}/pf_gp_exceptions_t.c)

add_enclave(TARGET sgx_pf_gp_exceptions_enc_unsigned SOURCES enc.c props_pfgp.c
            ${CMAKE_CURRENT_BINARY_DIR}/pf_gp_exceptions_t.c)

enclave_include_directories(sgx_pf_gp_exceptions_enc PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})

enclave_include_directories(sgx_pf_gp_exceptions_enc_unsigned PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})

add_enclave(
  TARGET
  sgx_simulate_pf_gp_exceptions_enc
  CONFIG
  sign_nopfgp.conf
  SOURCES
  enc.c
  props_nopfgp.c
  ${CMAKE_CURRENT_BINARY_DIR}/pf_gp_exceptions_t.c)

add_enclave(TARGET sgx_simulate_pf_gp_exceptions_enc_unsigned SOURCES enc.c
            props_nopfgp.c ${CMAKE_CURRENT_BINARY_DIR}/pf_gp_exceptions_t.c)

enclave_include_directories(sgx_simulate_pf_gp_exceptions_enc PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})

enclave_include_directories(sgx_simulate_pf_gp_exceptions_enc_unsigned PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})
