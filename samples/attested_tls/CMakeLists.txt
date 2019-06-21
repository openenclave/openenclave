# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.11)

project("Attested TLS sample" LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 11)

find_package(OpenEnclave CONFIG REQUIRED)

add_subdirectory(server)
add_subdirectory(client)
add_subdirectory(non_enc_client)
add_subdirectory(tls_between_enclaves)
add_subdirectory(tls_between_non_enclave_enclave)


# generate key-pair for both client and server
add_custom_command(OUTPUT client_private.pem client_public.pem server_private.pem server_public.pem
  COMMAND openssl genrsa -out ${CMAKE_BINARY_DIR}/client/enc/client_private.pem -3 3072
  COMMAND openssl rsa -in ${CMAKE_BINARY_DIR}/client/enc/client_private.pem -pubout -out ${CMAKE_BINARY_DIR}/client/enc/client_public.pem
  COMMAND openssl genrsa -out ${CMAKE_BINARY_DIR}/server/enc/server_private.pem -3 3072
  COMMAND openssl rsa -in ${CMAKE_BINARY_DIR}/server/enc/server_private.pem -pubout -out ${CMAKE_BINARY_DIR}/server/enc/server_public.pem)

# Generate public key header files
add_custom_command(OUTPUT tls_client_enc_pubkey.h tls_server_enc_pubkey.h
  DEPENDS ${CMAKE_SOURCE_DIR}/scripts/gen_pubkey_header.sh
  COMMAND ${CMAKE_SOURCE_DIR}/scripts/gen_pubkey_header.sh ${CMAKE_SOURCE_DIR}/client/enc/tls_client_enc_pubkey.h ${CMAKE_BINARY_DIR}/client/enc/client_public.pem
  COMMAND ${CMAKE_SOURCE_DIR}/scripts/gen_pubkey_header.sh ${CMAKE_SOURCE_DIR}/server/enc/tls_server_enc_pubkey.h ${CMAKE_BINARY_DIR}/server/enc/server_public.pem
  COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_SOURCE_DIR}/server/enc/tls_server_enc_pubkey.h ${CMAKE_SOURCE_DIR}/client/enc/tls_server_enc_pubkey.h
  COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_SOURCE_DIR}/server/enc/tls_server_enc_pubkey.h ${CMAKE_SOURCE_DIR}/non_enc_client/tls_server_enc_pubkey.h
  COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_SOURCE_DIR}/client/enc/tls_client_enc_pubkey.h ${CMAKE_SOURCE_DIR}/server/enc/tls_client_enc_pubkey.h)


add_custom_target(build_common DEPENDS client_private.pem server_public.pem tls_client_enc_pubkey.h tls_server_enc_pubkey.h tls_client_enc_pubkey.h)

if ((NOT DEFINED ENV{OE_SIMULATION}) OR (NOT $ENV{OE_SIMULATION}))
  add_custom_target(run
    DEPENDS tls_server tls_client tls_non_enc_client tls_client_enc tls_server_enc
    COMMAND ${CMAKE_BINARY_DIR}/server/host/tls_server_host ${CMAKE_BINARY_DIR}/server/enc/tls_server_enc.signed -port:12341 &
    COMMAND ${CMAKE_COMMAND} -E sleep 2
    COMMAND ${CMAKE_BINARY_DIR}/client/host/tls_client_host ${CMAKE_BINARY_DIR}/client/enc/tls_client_enc.signed -server:localhost -port:12341
    COMMAND ${CMAKE_COMMAND} -E sleep 2
    COMMAND ${CMAKE_BINARY_DIR}/server/host/tls_server_host ${CMAKE_BINARY_DIR}/server/enc/tls_server_enc.signed -port:12341 &
    COMMAND ${CMAKE_COMMAND} -E sleep 2
    COMMAND ${CMAKE_BINARY_DIR}/non_enc_client/tls_non_enc_client -server:localhost -port:12341)
endif ()
