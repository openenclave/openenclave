# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_custom_command(
  OUTPUT ${PROJ}_t.h ${PROJ}_t.c ${PROJ}_args.h
  DEPENDS ../${PROJ}.edl edger8r
  COMMAND edger8r --trusted ${CMAKE_CURRENT_SOURCE_DIR}/../${PROJ}.edl
          --search-path ${PROJECT_SOURCE_DIR}/include -DOE_SGX)

# generate the enclave and sign it with the private key
add_enclave(
  TARGET
  ${PROJ}_enc
  CRYPTO_LIB
  openssl
  SOURCES
  enc.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/${PROJ}_t.c
  CONFIG
  enc.conf
  KEY
  ${CMAKE_CURRENT_BINARY_DIR}/../${PROJ}_enc_private.pem)

add_enclave_dependencies(${PROJ}_enc ${PROJ}_enclave_key_pair)

# Need for the generated file ${PROJ}_t.h
enclave_include_directories(${PROJ}_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

enclave_link_libraries(${PROJ}_enc oeenclave oelibc)

add_custom_target(${PROJ}_enclave_signed DEPENDS ${PROJ}_enc.signed
                                                 ${PROJ}_enc_pubkey.h)
