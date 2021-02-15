# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../common/crypto_crls_cert_chains.edl)

add_custom_command(
  OUTPUT crypto_crls_cert_chains_t.h crypto_crls_cert_chains_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  crypto-extra_enc
  UUID
  69840c14-42f8-4637-9d58-57bccb5a0532
  CXX
  SOURCES
  enc.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/crypto_crls_cert_chains_t.c)

enclave_include_directories(crypto-extra_enc PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})
