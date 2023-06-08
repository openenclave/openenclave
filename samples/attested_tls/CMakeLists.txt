# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.11)

# If the CC environment variable has been specified or if the CMAKE_C_COMPILER
# cmake variable has been passed to cmake, use the C compiler that has been
# specified. Otherwise, prefer clang. Same for C++ compiler.
# This must be done before the `project` command.
if (UNIX)
  if (NOT DEFINED ENV{CC} AND NOT DEFINED CMAKE_C_COMPILER)
    find_program(CMAKE_C_COMPILER clang-11 clang-10 clang)
  endif ()
  if (NOT DEFINED ENV{CXX} AND NOT DEFINED CMAKE_CXX_COMPILER)
    find_program(CMAKE_CXX_COMPILER clang++-11 clang++-10 clang++)
  endif ()
endif ()

project("Attested TLS sample" LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 11)
# set OE_CRYPTO_LIB to either "mbedtls" or "openssl" based on the crypto wrapper to be used.
# OE_CRYPTO_LIB is case sensitive. Use all lowercase letters.
set(OE_CRYPTO_LIB
    mbedtls
    CACHE STRING "Crypto library used by enclaves.")

find_package(OpenEnclave CONFIG REQUIRED)

if (OE_CRYPTO_LIB STREQUAL "openssl_symcrypt_fips")
  # Download the SymCrypt release package at config-time
  include(FetchContent)
  FetchContent_Declare(
    symcrypt_pkg
    SOURCE_DIR ${CMAKE_BINARY_DIR}/SymCrypt
    URL https://github.com/microsoft/SymCrypt/releases/download/v103.0.1/symcrypt-linux-oe_full-AMD64-103.0.1-69dbff3.tar.gz
    URL_HASH
      SHA256=27C8C1C309B217E74D6055734D305AA86D8CE9E05D6D75AFD12C885F13CEA710)

  # Make the downloaded package globally available
  FetchContent_GetProperties(symcrypt_pkg)
  if (NOT symcrypt_pkg_POPULATED)
    FetchContent_Populate(symcrypt_pkg)
  endif ()

  # The linker can only resolve up to single number after .so
  configure_file(${CMAKE_BINARY_DIR}/SymCrypt/lib/libsymcrypt.so.103.0.1
                 ${CMAKE_BINARY_DIR}/libsymcrypt.so.103 COPYONLY)

  # Option passed in oeedger8r to include entropy.edl (required by
  # SymCrypt FIPS module)
  set(EDL_USE_HOST_ENTROPY "-DEDL_USE_HOST_ENTROPY")
endif ()

add_subdirectory(server)
add_subdirectory(client)
add_subdirectory(non_enc_client)

if ((NOT DEFINED ENV{OE_SIMULATION}) OR (NOT $ENV{OE_SIMULATION}))
  add_custom_target(
    run
    DEPENDS tls_server tls_client tls_non_enc_client tls_client_enc
            tls_server_enc
    COMMENT "Launch processes to establish an Attested TLS between two enclaves"
    COMMAND
      bash -c
      "${CMAKE_BINARY_DIR}/server/host/tls_server_host ${CMAKE_BINARY_DIR}/server/enc/tls_server_enc.signed -port:12341 &"
    COMMAND ${CMAKE_COMMAND} -E sleep 2
    COMMAND
      ${CMAKE_BINARY_DIR}/client/host/tls_client_host
      ${CMAKE_BINARY_DIR}/client/enc/tls_client_enc.signed -server:localhost
      -port:12341
    COMMAND ${CMAKE_COMMAND} -E sleep 2
    COMMENT
      "Launch processes to establish an Attested TLS between an non-enclave TLS client and an TLS server running inside an enclave "
    COMMAND
      bash -c
      "${CMAKE_BINARY_DIR}/server/host/tls_server_host ${CMAKE_BINARY_DIR}/server/enc/tls_server_enc.signed -port:12345 &"
    COMMAND ${CMAKE_COMMAND} -E sleep 2
    COMMAND ${CMAKE_BINARY_DIR}/non_enc_client/tls_non_enc_client
            -server:localhost -port:12345)
endif ()
