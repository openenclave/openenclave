# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(OECRYPTO_OPENSSL_SOURCE
    ${PROJECT_SOURCE_DIR}/3rdparty/mbedtls/mbedtls/library/oid.c
    ${PROJECT_SOURCE_DIR}/common/asn1.c
    ${PROJECT_SOURCE_DIR}/common/cert.c
    ${PROJECT_SOURCE_DIR}/common/kdf.c
    ${PROJECT_SOURCE_DIR}/common/crypto/openssl/asn1.c
    ${PROJECT_SOURCE_DIR}/common/crypto/openssl/cert.c
    ${PROJECT_SOURCE_DIR}/common/crypto/openssl/cmac.c
    ${PROJECT_SOURCE_DIR}/common/crypto/openssl/crl.c
    ${PROJECT_SOURCE_DIR}/common/crypto/openssl/ec.c
    ${PROJECT_SOURCE_DIR}/common/crypto/openssl/hmac.c
    ${PROJECT_SOURCE_DIR}/common/crypto/openssl/key.c
    ${PROJECT_SOURCE_DIR}/common/crypto/openssl/rsa.c
    ${PROJECT_SOURCE_DIR}/common/crypto/openssl/sha.c
    cert.c
    entropy.c
    gcm.c
    init.c
    symcrypt_engine.c)

# key.c requires deprecated APIs that have no direct equivalent in OpenSSL 3
set_source_files_properties(
  ${PROJECT_SOURCE_DIR}/common/crypto/openssl/key.c
  PROPERTIES COMPILE_FLAGS "-Wno-deprecated-declarations")

add_enclave_library(oecryptoopenssl STATIC ${OECRYPTO_OPENSSL_SOURCE})

enclave_compile_definitions(oecryptoopenssl PRIVATE OECRYPTO_OPENSSL_VER=1)

add_enclave_library(oecryptoopenssl_3 STATIC ${OECRYPTO_OPENSSL_SOURCE})

enclave_compile_definitions(oecryptoopenssl_3 PRIVATE OECRYPTO_OPENSSL_VER=3)

maybe_build_using_clangw(oecryptoopenssl)
maybe_build_using_clangw(oecryptoopenssl_3)

enclave_enable_code_coverage(oecryptoopenssl)
enclave_enable_code_coverage(oecryptoopenssl_3)

enclave_include_directories(
  oecryptoopenssl PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/3rdparty/mbedtls/mbedtls/include>
  $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/3rdparty/mbedtls>)

enclave_include_directories(
  oecryptoopenssl_3 PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
  $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/3rdparty/mbedtls/mbedtls/include>
  $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/3rdparty/mbedtls>)

enclave_link_libraries(oecryptoopenssl PUBLIC openssl)
enclave_link_libraries(oecryptoopenssl_3 PUBLIC openssl_3)

# Enforce the correct build dependency such that OpenSSL will be built first.
add_enclave_dependencies(oecryptoopenssl openssl)
add_enclave_dependencies(oecryptoopenssl_3 openssl_3)

set_enclave_property(TARGET oecryptoopenssl PROPERTY ARCHIVE_OUTPUT_DIRECTORY
                     ${OE_LIBDIR}/openenclave/enclave)
set_enclave_property(TARGET oecryptoopenssl_3 PROPERTY ARCHIVE_OUTPUT_DIRECTORY
                     ${OE_LIBDIR}/openenclave/enclave)

install_enclaves(
  TARGETS
  oecryptoopenssl
  EXPORT
  openenclave-targets
  ARCHIVE
  DESTINATION
  ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)

install_enclaves(
  TARGETS
  oecryptoopenssl_3
  EXPORT
  openenclave-targets
  ARCHIVE
  DESTINATION
  ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
