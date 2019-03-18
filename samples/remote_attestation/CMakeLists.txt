# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.10)

project("Remote Attestation Sample" LANGUAGES C CXX)

find_package(OpenEnclave CONFIG REQUIRED)

set(CMAKE_CXX_STANDARD 11)

add_subdirectory(common)
add_subdirectory(enc1)
add_subdirectory(enc2)
add_subdirectory(host)

# Generate key A
add_custom_command(OUTPUT private_a.pem public_a.pem
  COMMAND openssl genrsa -out private_a.pem -3 3072
  COMMAND openssl rsa -in private_a.pem -pubout -out public_a.pem)

# Generate key B
add_custom_command(OUTPUT private_b.pem public_b.pem
  COMMAND openssl genrsa -out private_b.pem -3 3072
  COMMAND openssl rsa -in private_b.pem -pubout -out public_b.pem)

# Sign enclave A with key A
add_custom_command(OUTPUT enc1/enclave_a.signed
  DEPENDS ${CMAKE_BINARY_DIR}/private_a.pem ${CMAKE_BINARY_DIR}/enc2/enc1_pubkey.h
  COMMAND openenclave::oesign sign $<TARGET_FILE:enclave_a> ${CMAKE_SOURCE_DIR}/enc1/enc.conf private_a.pem)

# Sign enclave B with key B
add_custom_command(OUTPUT enc2/enclave_b.signed
  DEPENDS ${CMAKE_BINARY_DIR}/private_b.pem ${CMAKE_BINARY_DIR}/enc1/enc2_pubkey.h
  COMMAND openenclave::oesign sign $<TARGET_FILE:enclave_b> ${CMAKE_SOURCE_DIR}/enc2/enc.conf private_b.pem)

# The following is needed to make enclaves aware about the keys
add_custom_target(public_key_a DEPENDS public_a.pem)
add_custom_target(public_key_b DEPENDS public_b.pem)

add_custom_target(run
  DEPENDS remote_attestation_host ${CMAKE_BINARY_DIR}/enc1/enclave_a.signed ${CMAKE_BINARY_DIR}/enc2/enclave_b.signed
  COMMAND remote_attestation_host ${CMAKE_BINARY_DIR}/enc1/enclave_a.signed ${CMAKE_BINARY_DIR}/enc2/enclave_b.signed)
