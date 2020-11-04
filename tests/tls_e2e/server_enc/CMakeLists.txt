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
  mbedtls_tls_server_enc
  CRYPTO_LIB
  mbedtls
  SOURCES
  mbedtls_server.cpp
  ../common/mbedtls_utility.cpp
  ../common/utility.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/tls_e2e_t.c)

set_source_files_properties(tls_e2e_t.c PROPERTIES COMPILE_FLAGS
                                                   "-Wno-conversion")

enclave_include_directories(mbedtls_tls_server_enc PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})

enclave_link_libraries(mbedtls_tls_server_enc oeenclave openssl oelibc
                       oehostsock oehostresolver)

if (BUILD_OPENSSL)

  add_enclave(
    TARGET
    openssl_tls_server_enc
    CRYPTO_LIB
    openssl
    SOURCES
    openssl_server.cpp
    ../common/utility.cpp
    ../common/openssl_utility.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/tls_e2e_t.c)

  enclave_include_directories(openssl_tls_server_enc PRIVATE
                              ${CMAKE_CURRENT_BINARY_DIR})

  enclave_link_libraries(openssl_tls_server_enc oehostsock oehostresolver)
endif ()
