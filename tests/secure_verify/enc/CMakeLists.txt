# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_custom_command(
  OUTPUT secure_verify_t.h secure_verify_t.c secure_verify_args.h
  DEPENDS ../secure_verify.edl edger8r
  COMMAND edger8r --trusted ${CMAKE_CURRENT_SOURCE_DIR}/../secure_verify.edl
          --search-path ${PROJECT_SOURCE_DIR}/include -DOE_SGX)

# generate the enclave and sign it with the private key
add_enclave(
  TARGET
  secure_verify_enc_mbedtls
  SOURCES
  enc.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/secure_verify_t.c
  CONFIG
  enc.conf
  KEY
  ${CMAKE_CURRENT_BINARY_DIR}/../secure_verify_enc_private.pem)

# generate the enclave and sign it with the private key
add_enclave(
  TARGET
  secure_verify_enc_openssl
  CRYPTO_LIB
  openssl
  SOURCES
  enc.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/secure_verify_t.c
  CONFIG
  enc.conf
  KEY
  ${CMAKE_CURRENT_BINARY_DIR}/../secure_verify_enc_private.pem)

add_enclave_dependencies(secure_verify_enc_mbedtls
                         secure_verify_enclave_key_pair)
add_enclave_dependencies(secure_verify_enc_openssl
                         secure_verify_enclave_key_pair)

# Need for the generated file secure_verify_t.h
enclave_include_directories(secure_verify_enc_mbedtls PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})
enclave_include_directories(secure_verify_enc_openssl PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})

enclave_link_libraries(secure_verify_enc_mbedtls oeenclave oelibc)
enclave_link_libraries(secure_verify_enc_openssl oeenclave oelibc)

# Generate the oecert binary in the the same directory with enclave binary
set_target_properties(
  secure_verify_enc_mbedtls PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                                       "${CMAKE_CURRENT_BINARY_DIR}/..")
set_target_properties(
  secure_verify_enc_openssl PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                                       "${CMAKE_CURRENT_BINARY_DIR}/..")

add_custom_target(
  secure_verify_enclave_mbedtls_signed DEPENDS secure_verify_enc_mbedtls.signed
                                               secure_verify_enc_pubkey.h)
add_custom_target(
  secure_verify_enclave_openssl_signed DEPENDS secure_verify_enc_openssl.signed
                                               secure_verify_enc_pubkey.h)
