# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../sealKey.edl)

add_custom_command(
  OUTPUT sealKey_t.h sealKey_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  sealKey_mbedtls_enc
  UUID
  ab200889-df37-440e-9c5c-e78a9ce6579e
  CXX
  CRYPTO_LIB
  mbedtls
  SOURCES
  enc.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/sealKey_t.c)

enclave_include_directories(
  sealKey_mbedtls_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR})

enclave_compile_features(sealKey_mbedtls_enc PRIVATE
                         cxx_generalized_initializers)

if (BUILD_OPENSSL)
  add_enclave(
    TARGET
    sealKey_openssl_enc
    UUID
    a51eb68b-5f3e-4a20-b620-c1184548c8fa
    CXX
    CRYPTO_LIB
    OpenSSL
    SOURCES
    enc.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/sealKey_t.c)

  enclave_include_directories(
    sealKey_openssl_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})

  enclave_compile_features(sealKey_openssl_enc PRIVATE
                           cxx_generalized_initializers)

  add_enclave(
    TARGET
    sealKey_openssl_3_enc
    UUID
    7d5d378e-49f8-478e-9dd8-abaa9a160bbe
    CXX
    CRYPTO_LIB
    OpenSSL_3
    SOURCES
    enc.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/sealKey_t.c)

  enclave_include_directories(
    sealKey_openssl_3_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR})

  enclave_compile_features(sealKey_openssl_3_enc PRIVATE
                           cxx_generalized_initializers)
endif ()
