# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Use the edger8r to generate C bindings from the EDL file.
add_custom_command(
  OUTPUT tls_server_t.h tls_server_t.c tls_server_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/server/tls_server.edl
  COMMAND
    openenclave::oeedger8r --trusted ${CMAKE_SOURCE_DIR}/server/tls_server.edl
    --search-path ${OE_INCLUDEDIR} --search-path
    ${OE_INCLUDEDIR}/openenclave/edl/sgx)

# Sign enclave and generate a header file for server's MRENCLAVE
add_custom_command(
  OUTPUT tls_server_enc.signed tls_server_enc_mrenclave.h
  DEPENDS tls_server_enc enc.conf ${CMAKE_SOURCE_DIR}/server/enc/private.pem
          ${CMAKE_SOURCE_DIR}/scripts/gen_mrenclave_header.sh
  COMMAND
    openenclave::oesign sign -e $<TARGET_FILE:tls_server_enc> -c
    ${CMAKE_SOURCE_DIR}/server/enc/enc.conf -k
    ${CMAKE_SOURCE_DIR}/server/enc/private.pem
  COMMAND openenclave::oesign dump -e tls_server_enc.signed > temp.dmp
  COMMAND bash ${CMAKE_SOURCE_DIR}/scripts/gen_mrenclave_header.sh
          ${CMAKE_SOURCE_DIR}/common/tls_server_enc_mrenclave.h temp.dmp
  COMMAND ${CMAKE_COMMAND} -E sleep 1
  COMMAND ${CMAKE_COMMAND} -E remove temp.dmp)

if (${OE_CRYPTO_LIB} MATCHES "openssl")
  message(${OE_CRYPTO_LIB})
  add_executable(
    tls_server_enc
    ecalls.cpp ${OE_CRYPTO_LIB}/server.cpp ../../../common/utility.cpp
    ../../../common/openssl_utility.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/tls_server_t.c)
elseif (${OE_CRYPTO_LIB} MATCHES "mbedtls")
  message(${OE_CRYPTO_LIB})
  add_executable(
    tls_server_enc
    ecalls.cpp ${OE_CRYPTO_LIB}/server.cpp ${OE_CRYPTO_LIB}/cert_verifier.cpp
    ${OE_CRYPTO_LIB}/identity_verifier.cpp ../../../common/utility.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/tls_server_t.c)
endif ()

if (WIN32)
  maybe_build_using_clangw(tls_server_enc)
endif ()

target_compile_definitions(tls_server_enc PUBLIC OE_API_VERSION=2)

target_include_directories(
  tls_server_enc
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}
          ${CMAKE_BINARY_DIR}/server/enc)

if (${OE_CRYPTO_LIB} MATCHES "openssl")
  target_link_libraries(
    tls_server_enc openenclave::oeenclave openenclave::openssl
    openenclave::oelibcxx openenclave::oehostsock openenclave::oehostresolver)
elseif (${OE_CRYPTO_LIB} MATCHES "mbedtls")
  target_link_libraries(
    tls_server_enc openenclave::oeenclave openenclave::oelibcxx
    openenclave::oehostsock openenclave::oehostresolver)
endif ()

add_custom_target(tls_server_sign_enc ALL DEPENDS tls_server_enc.signed
                                                  tls_server_enc_mrenclave.h)
