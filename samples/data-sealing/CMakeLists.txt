# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.11)

project("Data Sealing Sample" LANGUAGES C CXX)

find_package(OpenEnclave CONFIG REQUIRED)

set(CMAKE_CXX_STANDARD 11)

add_subdirectory(common)
add_subdirectory(enclave_a_v1)
add_subdirectory(enclave_a_v2)
add_subdirectory(enclave_b)
add_subdirectory(host)

# Generate key A
add_custom_command(
  OUTPUT private_a.pem public_a.pem
  COMMAND openssl genrsa -out private_a.pem -3 3072
  COMMAND openssl rsa -in private_a.pem -pubout -out public_a.pem)

# Sign enclave A v1 with key A
add_custom_command(
  OUTPUT enclave_a_v1/enclave_a_v1.signed
  DEPENDS enclave_a_v1 enclave_a_v1/data-sealing.conf private_a.pem
  COMMAND openenclave::oesign sign -e $<TARGET_FILE:enclave_a_v1> -c
          ${CMAKE_SOURCE_DIR}/enclave_a_v1/data-sealing.conf -k private_a.pem)

add_custom_target(enclave_a_v1_signed DEPENDS enclave_a_v1/enclave_a_v1.signed)

# Sign enclave A v2 with key A
add_custom_command(
  OUTPUT enclave_a_v2/enclave_a_v2.signed
  DEPENDS enclave_a_v2 enclave_a_v2/data-sealing.conf private_a.pem
  COMMAND openenclave::oesign sign -e $<TARGET_FILE:enclave_a_v2> -c
          ${CMAKE_SOURCE_DIR}/enclave_a_v2/data-sealing.conf -k private_a.pem)

add_custom_target(enclave_a_v2_signed DEPENDS enclave_a_v2/enclave_a_v2.signed)

# Generate key B
add_custom_command(
  OUTPUT private_b.pem public_b.pem
  COMMAND openssl genrsa -out private_b.pem -3 3072
  COMMAND openssl rsa -in private_b.pem -pubout -out public_b.pem)

# Sign enclave B with key B
add_custom_command(
  OUTPUT enclave_b/enclave_b.signed
  DEPENDS enclave_b enclave_b/data-sealing.conf private_b.pem
  COMMAND openenclave::oesign sign -e $<TARGET_FILE:enclave_b> -c
          ${CMAKE_SOURCE_DIR}/enclave_b/data-sealing.conf -k private_b.pem)

add_custom_target(enclave_b_signed DEPENDS enclave_b/enclave_b.signed)

add_custom_target(sign ALL DEPENDS enclave_a_v1_signed enclave_a_v2_signed
                                   enclave_b_signed)

add_custom_target(
  run
  DEPENDS data-sealing_host sign
  COMMAND
    data-sealing_host ${CMAKE_BINARY_DIR}/enclave_a_v1/enclave_a_v1.signed
    ${CMAKE_BINARY_DIR}/enclave_a_v2/enclave_a_v2.signed
    ${CMAKE_BINARY_DIR}/enclave_b/enclave_b.signed)
