# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../dcap_quoteprov_log.edl)

add_custom_command(
  OUTPUT dcap_quoteprov_log_t.h dcap_quoteprov_log_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  dcap_quoteprov_log_enc
  UUID
  c6d845e1-5fd6-4faf-9c73-d84e25d48fe0
  SOURCES
  enc.c
  ${CMAKE_CURRENT_BINARY_DIR}/dcap_quoteprov_log_t.c)

enclave_include_directories(dcap_quoteprov_log_enc PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})
