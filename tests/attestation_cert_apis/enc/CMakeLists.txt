# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../tls.edl)

add_custom_command(
  OUTPUT tls_t.h tls_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  tls_mbedtls_enc
  UUID
  6cc330ff-c8cf-49d4-92ef-e1674794f820
  CRYPTO_LIB
  mbedtls
  SOURCES
  enc.cpp
  mbedtls_rsa.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/tls_t.c)

enclave_include_directories(tls_mbedtls_enc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
                            ${CMAKE_CURRENT_BINARY_DIR})

if (BUILD_OPENSSL)
  add_enclave(
    TARGET
    tls_openssl_enc
    UUID
    f0b4503b-9a54-4a97-a712-15e48fe979bd
    CRYPTO_LIB
    openssl
    SOURCES
    enc.cpp
    openssl_rsa.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/tls_t.c)

  enclave_compile_definitions(tls_openssl_enc PRIVATE OE_USE_OPENSSL
                              OECRYPTO_OPENSSL_VER=1)

  enclave_include_directories(
    tls_openssl_enc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR})

  add_enclave(
    TARGET
    tls_openssl_3_enc
    UUID
    baf78480-37f1-405b-82d4-9fa0e322ac8e
    CRYPTO_LIB
    openssl_3
    SOURCES
    enc.cpp
    openssl_rsa.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/tls_t.c)

  enclave_compile_definitions(tls_openssl_3_enc PRIVATE OE_USE_OPENSSL
                              OECRYPTO_OPENSSL_VER=3)

  enclave_include_directories(
    tls_openssl_3_enc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR})
endif ()
