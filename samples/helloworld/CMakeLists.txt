# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.10)

project("Hello World Sample" LANGUAGES C CXX)

find_package(OpenEnclave CONFIG REQUIRED)

set(CMAKE_CXX_STANDARD 11)

add_subdirectory(enc)
add_subdirectory(host)

# Generate key
add_custom_command(OUTPUT private.pem public.pem
  COMMAND openssl genrsa -out private.pem -3 3072
  COMMAND openssl rsa -in private.pem -pubout -out public.pem)

# Sign enclave
add_custom_command(OUTPUT enc/enclave.signed
  DEPENDS ${CMAKE_BINARY_DIR}/private.pem
  COMMAND openenclave::oesign sign $<TARGET_FILE:enclave> ${CMAKE_SOURCE_DIR}/enc/helloworld.conf private.pem)

if (NOT DEFINED $ENV{OE_SIMULATION})
  add_custom_target(run
    DEPENDS helloworld_host ${CMAKE_BINARY_DIR}/enc/enclave.signed
    COMMAND helloworld_host ${CMAKE_BINARY_DIR}/enc/enclave.signed)
endif ()

add_custom_target(simulate
  DEPENDS helloworld_host ${CMAKE_BINARY_DIR}/enc/enclave.signed
  COMMAND helloworld_host ${CMAKE_BINARY_DIR}/enc/enclave.signed --simulate)
