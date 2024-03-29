# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../crypto.edl)

add_custom_command(
  OUTPUT crypto_t.h crypto_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

set(SRCS
    ../../read_file.c
    ../../asn1_tests.c
    ../../crl_tests.c
    ../../cert_tests.c
    ../../ec_tests.c
    ../../hash.c
    ../../hmac_tests.c
    ../../kdf_tests.c
    ../../random_tests.c
    ../../rsa_tests.c
    ../../sha_tests.c
    ../../tests.c
    ../../utils.c)

if (OE_SGX)
  list(APPEND SRCS ${PROJECT_SOURCE_DIR}/common/sgx/rand.S
       ../../cpu_entropy_test.c)
endif ()

add_enclave(
  TARGET
  crypto_mbedtls_enc
  UUID
  f0be7db0-ce7c-4dc4-b8c8-b161f4216225
  CRYPTO_LIB
  mbedtls
  SOURCES
  enc.c
  crypto_t.c
  ${SRCS})

if (CODE_COVERAGE)
  enclave_compile_definitions(crypto_mbedtls_enc PRIVATE CODE_COVERAGE)
endif ()

enclave_include_directories(crypto_mbedtls_enc PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})

enclave_link_libraries(crypto_mbedtls_enc)

if (BUILD_OPENSSL)
  add_enclave(
    TARGET
    crypto_openssl_enc
    UUID
    5643276b-836c-4212-b5fe-af55323bc22a
    CRYPTO_LIB
    OpenSSL
    SOURCES
    enc.c
    crypto_t.c
    ${SRCS})

  enclave_compile_definitions(crypto_openssl_enc PRIVATE OE_USE_OPENSSL)
  if (CODE_COVERAGE)
    enclave_compile_definitions(crypto_openssl_enc PRIVATE CODE_COVERAGE)
  endif ()

  enclave_include_directories(
    crypto_openssl_enc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR})

  enclave_link_libraries(crypto_openssl_enc oehostfs)

  add_enclave(
    TARGET
    crypto_openssl_3_enc
    UUID
    de090e7e-47bf-4a00-9185-17aebbfec380
    CRYPTO_LIB
    OpenSSL_3
    SOURCES
    enc.c
    crypto_t.c
    ${SRCS})

  enclave_compile_definitions(crypto_openssl_3_enc PRIVATE OE_USE_OPENSSL)
  if (CODE_COVERAGE)
    enclave_compile_definitions(crypto_openssl_3_enc PRIVATE CODE_COVERAGE)
  endif ()

  enclave_include_directories(
    crypto_openssl_3_enc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR})

  enclave_link_libraries(crypto_openssl_3_enc oehostfs)
endif ()
