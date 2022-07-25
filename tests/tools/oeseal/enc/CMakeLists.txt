# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_custom_command(
  OUTPUT oeseal_t.h oeseal_t.c oeseal_args.h
  DEPENDS ../oeseal.edl edger8r
  COMMAND edger8r --trusted ${CMAKE_CURRENT_SOURCE_DIR}/../oeseal.edl
          --search-path ${PROJECT_SOURCE_DIR}/include -DOE_SGX)

add_enclave(
  TARGET
  sgx_oeseal_enc
  CRYPTO_LIB
  openssl
  SOURCES
  enc.c
  ${CMAKE_CURRENT_BINARY_DIR}/oeseal_t.c)

enclave_link_libraries(sgx_oeseal_enc oeseal_gcmaes)

# Need for the generated file oeseal_t.h
enclave_include_directories(sgx_oeseal_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                            ${PROJECT_SOURCE_DIR}/enclave/core/sgx)
