# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.11)

if (NOT UNIX)
  message(FATAL "oeapkman is currently supported on linux only.")
endif ()

project("OEAPKMAN Sample" LANGUAGES C)

# Currently the `OpenEnclave` package depends on `project()`.
find_package(OpenEnclave CONFIG REQUIRED)

set(OE_CRYPTO_LIB
    mbedtls
    CACHE STRING "Crypto library used by enclaves.")

add_subdirectory(enclave)
add_subdirectory(host)

# Generate key
add_custom_command(
  OUTPUT private.pem public.pem
  COMMAND openssl genrsa -out private.pem -3 3072
  COMMAND openssl rsa -in private.pem -pubout -out public.pem)

# Sign enclave
add_custom_command(
  OUTPUT enclave/enclave.signed
  DEPENDS enclave enclave/sqlite.conf private.pem
  COMMAND openenclave::oesign sign -e $<TARGET_FILE:enclave> -c
          ${CMAKE_SOURCE_DIR}/enclave/sqlite.conf -k private.pem)

add_custom_target(sign ALL DEPENDS enclave/enclave.signed)

if ((NOT DEFINED ENV{OE_SIMULATION}) OR (NOT $ENV{OE_SIMULATION}))
  add_custom_target(
    run
    DEPENDS sqlite_host sign
    COMMAND sqlite_host ${CMAKE_BINARY_DIR}/enclave/enclave.signed)
endif ()

add_custom_target(
  simulate
  DEPENDS sqlite_host sign
  COMMAND sqlite_host ${CMAKE_BINARY_DIR}/enclave/enclave.signed --simulate)
