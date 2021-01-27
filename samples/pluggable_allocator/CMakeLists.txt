# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.11)

if (LVI_MITIGATION MATCHES ControlFlow)
  # Configure the cmake to use customized compilation toolchain.
  # This package has to be added before `project()`.
  find_package(OpenEnclave-LVI-Mitigation CONFIG REQUIRED)
else ()
  # Setting the cmake compiler when LVI mitigation is not enabled. If the CC
  # environment variable has been specified or the if CMAKE_C_COMPILER cmake
  # variable has been passed to cmake, use the C compiler that has been specified.
  # Otherwise, prefer clang. Same for C++ compiler. This must be done before
  # the `project` command.
  if (UNIX)
    if (NOT DEFINED ENV{CC} AND NOT DEFINED CMAKE_C_COMPILER)
      find_program(CMAKE_C_COMPILER clang-8 clang)
    endif ()
    if (NOT DEFINED ENV{CXX} AND NOT DEFINED CMAKE_CXX_COMPILER)
      find_program(CMAKE_CXX_COMPILER clang++-8 clang++)
    endif ()
  endif ()
endif ()

project("Pluggable Allocator Sample" LANGUAGES C CXX)

# Currently the `OpenEnclave` package depends on `project()`.
find_package(OpenEnclave CONFIG REQUIRED)

set(CMAKE_CXX_STANDARD 11)
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

# Sign enclaves
add_custom_command(
  OUTPUT enclave/enclave_default.signed
  DEPENDS enclave enclave/allocator_demo.conf private.pem
  COMMAND openenclave::oesign sign -e $<TARGET_FILE:enclave_default> -c
          ${CMAKE_SOURCE_DIR}/enclave/allocator_demo.conf -k private.pem)

add_custom_command(
  OUTPUT enclave/enclave_custom.signed
  DEPENDS enclave enclave/allocator_demo.conf private.pem
  COMMAND openenclave::oesign sign -e $<TARGET_FILE:enclave_custom> -c
          ${CMAKE_SOURCE_DIR}/enclave/allocator_demo.conf -k private.pem)

add_custom_target(sign ALL DEPENDS enclave/enclave_default.signed
                                   enclave/enclave_custom.signed)

if ((NOT DEFINED ENV{OE_SIMULATION}) OR (NOT $ENV{OE_SIMULATION}))
  add_custom_target(
    run
    DEPENDS allocator_demo_host sign
    COMMAND
      allocator_demo_host ${CMAKE_BINARY_DIR}/enclave/enclave_default.signed
      ${CMAKE_BINARY_DIR}/enclave/enclave_custom.signed)
endif ()

add_custom_target(
  simulate
  DEPENDS allocator_demo_host sign
  COMMAND
    allocator_demo_host ${CMAKE_BINARY_DIR}/enclave/enclave_default.signed
    ${CMAKE_BINARY_DIR}/enclave/enclave_custom.signed --simulate)
