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

project("File Encryptor Sample" LANGUAGES C CXX)

find_package(OpenEnclave CONFIG REQUIRED)

set(CMAKE_CXX_STANDARD 11)
set(OE_CRYPTO_LIB
    mbedtls
    CACHE STRING "Crypto library used by enclaves.")

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
  DEPENDS enclave enclave/common/file-encryptor.conf private.pem
  COMMAND openenclave::oesign sign -e $<TARGET_FILE:enclave> -c
          ${CMAKE_SOURCE_DIR}/enclave/common/file-encryptor.conf -k private.pem)

add_custom_target(sign ALL DEPENDS enclave/enclave.signed)

if ((NOT DEFINED ENV{OE_SIMULATION}) OR (NOT $ENV{OE_SIMULATION}))
  add_custom_target(
    run
    DEPENDS file-encryptor_host sign testfile
    COMMAND file-encryptor_host ${CMAKE_CURRENT_SOURCE_DIR}/testfile
            ${CMAKE_BINARY_DIR}/enclave/enclave.signed)
endif ()

add_custom_target(
  simulate
  DEPENDS file-encryptor_host sign testfile
  COMMAND file-encryptor_host ${CMAKE_CURRENT_SOURCE_DIR}/testfile
          ${CMAKE_BINARY_DIR}/enclave/enclave.signed --simulate)
