# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Use the edger8r to generate C bindings from the EDL file.
add_custom_command(
  OUTPUT tls_client_t.h tls_client_t.c tls_client_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/client/tls_client.edl
  COMMAND
    openenclave::oeedger8r --trusted ${CMAKE_SOURCE_DIR}/client/tls_client.edl
    --search-path ${OE_INCLUDEDIR} --search-path
    ${OE_INCLUDEDIR}/openenclave/edl/sgx)

# Sign enclave
add_custom_command(
  OUTPUT tls_client_enc.signed
  DEPENDS tls_client_enc enc.conf ${CMAKE_SOURCE_DIR}/client/enc/private.pem
  COMMAND
    openenclave::oesign sign -e $<TARGET_FILE:tls_client_enc> -c
    ${CMAKE_SOURCE_DIR}/client/enc/enc.conf -k
    ${CMAKE_SOURCE_DIR}/client/enc/private.pem)

add_executable(
  tls_client_enc
  ecalls.cpp client.cpp cert_verifier.cpp identity_verifier.cpp
  ../../common/utility.cpp ${CMAKE_CURRENT_BINARY_DIR}/tls_client_t.c)

add_dependencies(tls_client_enc tls_server_sign_enc)

if (WIN32)
  maybe_build_using_clangw(tls_client_enc)
endif ()

target_compile_definitions(tls_client_enc PUBLIC OE_API_VERSION=2)

target_include_directories(
  tls_client_enc
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}
          ${CMAKE_BINARY_DIR}/client/enc)

target_link_libraries(
  tls_client_enc openenclave::oeenclave openenclave::oelibcxx
  openenclave::oehostsock openenclave::oehostresolver)

add_custom_target(tls_client_sign_enc ALL DEPENDS tls_client_enc.signed)
