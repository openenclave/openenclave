# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../common/crypto_crls_cert_chains.edl)

add_custom_command(
  OUTPUT crypto_crls_cert_chains_u.h crypto_crls_cert_chains_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND edger8r --untrusted ${EDL_FILE} --search-path
          ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(crypto-extra_host host.cpp crypto_crls_cert_chains_u.c)
add_dependencies(crypto-extra_host crypto_crls_cert_chains_test_data)
target_include_directories(crypto-extra_host
                           PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(crypto-extra_host oehost)
