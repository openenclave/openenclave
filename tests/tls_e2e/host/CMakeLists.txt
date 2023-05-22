# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../tls_e2e.edl)

add_custom_command(
  OUTPUT tls_e2e_u.h tls_e2e_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(mbedtls_tls_e2e_host host.cpp tls_e2e_u.c)

target_include_directories(
  mbedtls_tls_e2e_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                               ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(mbedtls_tls_e2e_host oehost)

if (BUILD_OPENSSL)
  add_executable(openssl_tls_e2e_host host.cpp tls_e2e_u.c)

  target_include_directories(
    openssl_tls_e2e_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                                 ${CMAKE_CURRENT_SOURCE_DIR})

  enclave_compile_definitions(openssl_tls_e2e_host PRIVATE OE_USE_OPENSSL)
  # target_compile_options(openssl_tls_e2e_host PRIVATE -Wno-deprecated-declarations)
  target_link_libraries(openssl_tls_e2e_host oehost)
endif ()
