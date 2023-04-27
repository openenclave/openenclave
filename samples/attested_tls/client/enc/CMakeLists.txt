# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Use the edger8r to generate C bindings from the EDL file.
add_custom_command(
  OUTPUT tls_client_t.h tls_client_t.c tls_client_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/client/tls_client.edl
  COMMAND
    openenclave::oeedger8r --trusted ${CMAKE_SOURCE_DIR}/client/tls_client.edl
    --search-path ${OE_INCLUDEDIR} --search-path
    ${OE_INCLUDEDIR}/openenclave/edl/sgx ${EDL_USE_HOST_ENTROPY})

# Sign enclave
add_custom_command(
  OUTPUT tls_client_enc.signed
  DEPENDS tls_client_enc enc.conf ${CMAKE_SOURCE_DIR}/client/enc/private.pem
  COMMAND
    openenclave::oesign sign -e $<TARGET_FILE:tls_client_enc> -c
    ${CMAKE_SOURCE_DIR}/client/enc/enc.conf -k
    ${CMAKE_SOURCE_DIR}/client/enc/private.pem)

if (${OE_CRYPTO_LIB} STREQUAL "openssl" OR ${OE_CRYPTO_LIB} STREQUAL
                                           "openssl_symcrypt_fips")
  add_executable(
    tls_client_enc
    ecalls.cpp
    openssl_client.cpp
    cert_verify_config.cpp
    ../../common/verify_callback.cpp
    ../../common/utility.cpp
    ../../common/openssl_utility.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/tls_client_t.c)
elseif (${OE_CRYPTO_LIB} STREQUAL "mbedtls")
  add_executable(
    tls_client_enc
    ecalls.cpp
    mbedtls_client.cpp
    cert_verify_config.cpp
    ../../common/cert_verifier.cpp
    ../../common/identity_verifier.cpp
    ../../common/utility.cpp
    ../../common/mbedtls_utility.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/tls_client_t.c)
endif ()

add_dependencies(tls_client_enc tls_server_sign_enc)

if (WIN32)
  maybe_build_using_clangw(tls_client_enc)
endif ()

target_compile_definitions(tls_client_enc PUBLIC OE_API_VERSION=2)

target_include_directories(
  tls_client_enc
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}
          ${CMAKE_BINARY_DIR}/client/enc)

if (${OE_CRYPTO_LIB} STREQUAL "openssl")
  target_link_libraries(
    tls_client_enc openenclave::oeenclave openenclave::oecryptoopenssl
    openenclave::oelibcxx openenclave::oehostsock openenclave::oehostresolver)
elseif (${OE_CRYPTO_LIB} STREQUAL "openssl_3")
  target_link_libraries(
    tls_client_enc openenclave::oeenclave openenclave::oecryptoopenssl_3
    openenclave::oelibcxx openenclave::oehostsock openenclave::oehostresolver)
elseif (${OE_CRYPTO_LIB} STREQUAL "mbedtls")
  target_link_libraries(
    tls_client_enc openenclave::oeenclave openenclave::oecryptombedtls
    openenclave::oelibcxx openenclave::oehostsock openenclave::oehostresolver)
elseif (${OE_CRYPTO_LIB} STREQUAL "openssl_symcrypt_fips")
  add_custom_command(
    TARGET tls_client_enc
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_BINARY_DIR}/libsymcrypt.so.103
            ${CMAKE_CURRENT_BINARY_DIR}/libsymcrypt.so.103)

  target_link_libraries(
    tls_client_enc
    openenclave::oeenclave
    openenclave::oesymcryptengine
    openenclave::oecryptoopenssl
    # Workaround: refer to the root of the build location so that we don't rely on the
    # order of copy
    ${CMAKE_BINARY_DIR}/libsymcrypt.so.103
    openenclave::oelibcxx
    openenclave::oehostsock
    openenclave::oehostresolver)
endif ()

add_custom_target(tls_client_sign_enc ALL DEPENDS tls_client_enc.signed)
