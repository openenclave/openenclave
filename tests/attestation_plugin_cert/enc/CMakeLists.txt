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
  tls_cert_mbedtls_enc
  UUID
  06999b6d-4132-461a-94da-f3972f68f301
  CRYPTO_LIB
  mbedtls
  SOURCES
  enc.cpp
  mbedtls_rsa.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/tls_t.c)

enclave_include_directories(
  tls_cert_mbedtls_enc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR})

if (BUILD_OPENSSL)
  add_enclave(
    TARGET
    tls_cert_openssl_enc
    UUID
    470f7d75-4c00-4f03-8125-f6e5175d0b7e
    CRYPTO_LIB
    openssl
    SOURCES
    enc.cpp
    openssl_rsa.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/tls_t.c)

  enclave_compile_definitions(tls_cert_openssl_enc PRIVATE OE_USE_OPENSSL
                              OECRYPTO_OPENSSL_VER=1)

  enclave_include_directories(
    tls_cert_openssl_enc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR})

  add_enclave(
    TARGET
    tls_cert_openssl_3_enc
    UUID
    f58b70e8-ecff-4509-ac5d-1315eed51fb8
    CRYPTO_LIB
    openssl_3
    SOURCES
    enc.cpp
    openssl_rsa.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/tls_t.c)

  enclave_compile_definitions(tls_cert_openssl_3_enc PRIVATE OE_USE_OPENSSL
                              OECRYPTO_OPENSSL_VER=3)

  enclave_include_directories(
    tls_cert_openssl_3_enc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR})
endif ()
