# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../symcrypt_provider.edl)
set(NO_ENTROPY_EDL_FILE ../symcrypt_provider_no_entropy.edl)

# Invoke oeedger8r to generate edge routines (*_t.c, *_t.h, and *_args.h)
add_custom_command(
  OUTPUT symcrypt_provider_t.h symcrypt_provider_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_custom_command(
  OUTPUT symcrypt_provider_no_entropy_t.h symcrypt_provider_no_entropy_t.c
  DEPENDS ${NO_ENTROPY_EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${NO_ENTROPY_EDL_FILE} --search-path
    ${PROJECT_SOURCE_DIR}/include ${DEFINE_OE_SGX} --search-path
    ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  sgx_symcrypt_provider_enc
  CRYPTO_LIB
  "SymCrypt_prov_FIPS"
  SOURCES
  enc.c
  ${CMAKE_CURRENT_BINARY_DIR}/symcrypt_provider_t.c)

add_enclave(
  TARGET
  sgx_symcrypt_provider_no_entropy_enc
  CRYPTO_LIB
  "SymCrypt_prov_FIPS"
  SOURCES
  enc.c
  ${CMAKE_CURRENT_BINARY_DIR}/symcrypt_provider_no_entropy_t.c)

if (ENABLE_SYMCRYPT_OPENSSL_TESTS)
  add_custom_command(
    TARGET sgx_symcrypt_provider_enc
    COMMAND
      ${CMAKE_COMMAND} -E copy
      ${CMAKE_BINARY_DIR}/3rdparty/symcrypt_provider/SymCrypt/lib/${SYMCRYPT_NAME}
      ${CMAKE_CURRENT_BINARY_DIR}/${SYMCRYPT_LINK_NAME})
  add_custom_command(
    TARGET sgx_symcrypt_provider_no_entropy_enc
    COMMAND
      ${CMAKE_COMMAND} -E copy
      ${CMAKE_BINARY_DIR}/3rdparty/symcrypt_provider/SymCrypt/lib/${SYMCRYPT_NAME}
      ${CMAKE_CURRENT_BINARY_DIR}/${SYMCRYPT_LINK_NAME})
endif ()

enclave_compile_definitions(sgx_symcrypt_provider_enc PRIVATE USE_ENTROPY_EDL)

# Add include paths
enclave_include_directories(sgx_symcrypt_provider_enc PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})

enclave_include_directories(sgx_symcrypt_provider_no_entropy_enc PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})
