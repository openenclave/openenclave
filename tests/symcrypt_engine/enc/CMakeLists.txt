# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../symcrypt_engine.edl)
set(NO_ENTROPY_EDL_FILE ../symcrypt_engine_no_entropy.edl)

add_enclave_library(symcrypt_engine_test STATIC symcrypt_engine_test.c)
enclave_link_libraries(symcrypt_engine_test oe_includes)
maybe_build_using_clangw(symcrypt_engine_test)

# Invoke oeedger8r to generate edge routines (*_t.c, *_t.h, and *_args.h)
add_custom_command(
  OUTPUT symcrypt_engine_t.h symcrypt_engine_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_custom_command(
  OUTPUT symcrypt_engine_no_entropy_t.h symcrypt_engine_no_entropy_t.c
  DEPENDS ${NO_ENTROPY_EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${NO_ENTROPY_EDL_FILE} --search-path
    ${PROJECT_SOURCE_DIR}/include ${DEFINE_OE_SGX} --search-path
    ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  sgx_symcrypt_engine_enc
  CRYPTO_LIB
  # Specify an unsupported option so that we can exercise the link-time
  # symbol replacement
  None
  SOURCES
  enc.c
  ${CMAKE_CURRENT_BINARY_DIR}/symcrypt_engine_t.c)

add_enclave(
  TARGET
  sgx_symcrypt_engine_no_entropy_enc
  CRYPTO_LIB
  # Specify an unsupported option so that we can exercise the link-time
  # symbol replacement
  None
  SOURCES
  enc.c
  ${CMAKE_CURRENT_BINARY_DIR}/symcrypt_engine_no_entropy_t.c)

enclave_compile_definitions(sgx_symcrypt_engine_enc PRIVATE USE_ENTROPY_EDL)

enclave_link_libraries(sgx_symcrypt_engine_enc symcrypt_engine_test
                       oecryptoopenssl)
enclave_link_libraries(sgx_symcrypt_engine_no_entropy_enc symcrypt_engine_test
                       oecryptoopenssl)

# Add include paths
enclave_include_directories(sgx_symcrypt_engine_enc PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})

enclave_include_directories(sgx_symcrypt_engine_no_entropy_enc PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})
