# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.11)

project("Data Sealing Sample" LANGUAGES C CXX)

find_package(OpenEnclave CONFIG REQUIRED)

set(CMAKE_CXX_STANDARD 11)

add_subdirectory(common)
add_subdirectory(enc1)
add_subdirectory(enc2)
add_subdirectory(enc3)
add_subdirectory(host)

# Generate key A
add_custom_command(OUTPUT private_a.pem public_a.pem
  COMMAND openssl genrsa -out private_a.pem -3 3072
  COMMAND openssl rsa -in private_a.pem -pubout -out public_a.pem)

# Sign enclave A v1 with key A
add_custom_command(OUTPUT enc1/enclave_a_v1.signed
  DEPENDS ${CMAKE_BINARY_DIR}/private_a.pem
  COMMAND openenclave::oesign sign -e $<TARGET_FILE:enclave_a_v1> -c ${CMAKE_SOURCE_DIR}/enc1/data-sealing.conf -k private_a.pem)

# Sign enclave A v2 with key A
add_custom_command(OUTPUT enc2/enclave_a_v2.signed
  DEPENDS ${CMAKE_BINARY_DIR}/private_a.pem
  COMMAND openenclave::oesign sign -e $<TARGET_FILE:enclave_a_v2> -c ${CMAKE_SOURCE_DIR}/enc2/data-sealing.conf -k private_a.pem)

# Generate key B
add_custom_command(OUTPUT private_b.pem public_b.pem
  COMMAND openssl genrsa -out private_b.pem -3 3072
  COMMAND openssl rsa -in private_b.pem -pubout -out public_b.pem)

# Sign enclave B with key B
add_custom_command(OUTPUT enc3/enclave_b.signed
  DEPENDS ${CMAKE_BINARY_DIR}/private_b.pem
  COMMAND openenclave::oesign sign -e $<TARGET_FILE:enclave_b> -c ${CMAKE_SOURCE_DIR}/enc3/data-sealing.conf -k private_b.pem)

add_custom_target(run
  DEPENDS data-sealing_host ${CMAKE_BINARY_DIR}/enc1/enclave_a_v1.signed ${CMAKE_BINARY_DIR}/enc2/enclave_a_v2.signed ${CMAKE_BINARY_DIR}/enc3/enclave_b.signed
  COMMAND data-sealing_host ${CMAKE_BINARY_DIR}/enc1/enclave_a_v1.signed ${CMAKE_BINARY_DIR}/enc2/enclave_a_v2.signed ${CMAKE_BINARY_DIR}/enc3/enclave_b.signed)
