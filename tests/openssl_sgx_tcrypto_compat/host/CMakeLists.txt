# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../openssl_sgx_tcrypto_compat.edl)

add_custom_command(
  OUTPUT openssl_sgx_tcrypto_compat_u.h openssl_sgx_tcrypto_compat_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(
  openssl_sgx_tcrypto_compat_host host.cpp digest_tests.cpp CSchema_checker.cpp
                                  openssl_sgx_tcrypto_compat_u.c)

target_include_directories(
  openssl_sgx_tcrypto_compat_host
  PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
          ${CMAKE_CURRENT_SOURCE_DIR}/../include
          ${OPENSSL_DIR}
          ${OPENSSL_DIR}/include
          ${CMAKE_BINARY_DIR}/3rdparty/openssl/build/include
          ${CMAKE_CURRENT_SOURCE_DIR}
          ${CMAKE_CURRENT_SOURCE_DIR}/../common_code)
target_link_libraries(openssl_sgx_tcrypto_compat_host oehost)
