# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../plugin.edl)

add_custom_command(
  OUTPUT plugin_t.h plugin_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  plugin_mbedtls_enc
  UUID
  0ed4cfa8-3d98-4ef6-a8e6-b3120517ccac
  CRYPTO_LIB
  mbedtls
  SOURCES
  enc.c
  ../plugin/tests.c
  ${CMAKE_CURRENT_BINARY_DIR}/plugin_t.c)

enclave_include_directories(plugin_mbedtls_enc PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})

if (BUILD_OPENSSL)
  add_enclave(
    TARGET
    plugin_openssl_enc
    UUID
    95e231ac-7c75-4ae4-9d37-8141aa2d1c62
    CRYPTO_LIB
    openssl
    SOURCES
    enc.c
    ../plugin/tests.c
    ${CMAKE_CURRENT_BINARY_DIR}/plugin_t.c)

  enclave_include_directories(plugin_openssl_enc PRIVATE
                              ${CMAKE_CURRENT_BINARY_DIR})

  target_compile_options(plugin_openssl_enc PRIVATE -Wno-deprecated-declarations)
endif ()
