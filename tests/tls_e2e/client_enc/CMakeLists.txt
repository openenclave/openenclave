# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../tls_e2e.edl)

add_custom_command(
  OUTPUT tls_e2e_t.h tls_e2e_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

set_source_files_properties(tls_e2e_t.c PROPERTIES COMPILE_FLAGS
                                                   "-Wno-conversion")

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

  enclave_link_libraries(openssl_tls_client_enc oehostsock oehostresolver)

  add_enclave(
    TARGET
    openssl_3_tls_client_enc
    CRYPTO_LIB
    openssl_3
    SOURCES
    openssl_client.cpp
    ../common/utility.cpp
    ../common/openssl_utility.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/tls_e2e_t.c)

  enclave_include_directories(openssl_3_tls_client_enc PRIVATE
                              ${CMAKE_CURRENT_BINARY_DIR})

  if (WIN32)
    enclave_compile_definitions(
      openssl_3_tls_client_enc PRIVATE
      $<$<CONFIG:Debug>:TLS_CLIENT_HEAP_PAGE_COUNT=4096>)
  endif ()

  enclave_link_libraries(openssl_3_tls_client_enc oehostsock oehostresolver)
endif ()
