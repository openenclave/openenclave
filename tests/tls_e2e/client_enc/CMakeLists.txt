# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../tls_e2e.edl)

add_custom_command(
  OUTPUT tls_e2e_t.h tls_e2e_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  mbedtls_tls_client_enc
  # Current implementation only supports Mbed TLS.
  CRYPTO_LIB
  mbedtls
  SOURCES
  mbedtls_client.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/tls_e2e_t.c
  ../common/utility.cpp
  ../common/mbedtls_utility.cpp
  tls_e2e_t.c)

set_source_files_properties(tls_e2e_t.c PROPERTIES COMPILE_FLAGS
                                                   "-Wno-conversion")

enclave_include_directories(
  mbedtls_tls_client_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR})

enclave_link_libraries(mbedtls_tls_client_enc oehostsock oehostresolver)

if (BUILD_OPENSSL)

  add_enclave(
    TARGET
    openssl_tls_client_enc
    CRYPTO_LIB
    openssl
    SOURCES
    openssl_client.cpp
    ../common/utility.cpp
    ../common/openssl_utility.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/tls_e2e_t.c)

  enclave_include_directories(openssl_tls_client_enc PRIVATE
                              ${CMAKE_CURRENT_BINARY_DIR})

  # target_compile_options(openssl_tls_client_enc PRIVATE -Wno-deprecated-declarations)
  enclave_link_libraries(openssl_tls_client_enc oehostsock oehostresolver)
endif ()
