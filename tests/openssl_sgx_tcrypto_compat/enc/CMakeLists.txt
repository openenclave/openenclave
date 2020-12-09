# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../openssl_sgx_tcrypto_compat.edl)

add_custom_command(
  OUTPUT openssl_sgx_tcrypto_compat_t.h openssl_sgx_tcrypto_compat_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  openssl_sgx_tcrypto_compat_enc
  CXX
  UUID
  90c020e8-e5dd-11ea-adc1-0242ac120002
  CRYPTO_LIB
  openssl
  SOURCES
  enc.cpp
  tests_ecalls.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../common_code/common_digest_tests.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/openssl_sgx_tcrypto_compat_t.c)

enclave_compile_definitions(tls_cert_openssl_enc PRIVATE OE_USE_OPENSSL)

enclave_include_directories(
  openssl_sgx_tcrypto_compat_enc
  PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${OPENSSL_DIR}
  ${OPENSSL_DIR}/include
  ${CMAKE_BINARY_DIR}/3rdparty/openssl/build/include
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/..
  ${CMAKE_CURRENT_SOURCE_DIR}/../common_code)
