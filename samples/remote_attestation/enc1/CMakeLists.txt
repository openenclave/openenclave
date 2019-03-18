# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Generate header needed by other enclaves for attestation
add_custom_command(OUTPUT enc1_pubkey.h
  DEPENDS public_key_a
  COMMAND ${CMAKE_SOURCE_DIR}/gen_pubkey_header.sh ${CMAKE_BINARY_DIR}/enc2/enc1_pubkey.h ${CMAKE_BINARY_DIR}/public_a.pem)

add_custom_target(enc1_pubkey_h DEPENDS enc1_pubkey.h)
add_custom_target(key_info_a DEPENDS public_key_a enc2_pubkey_h)

add_executable(enclave_a ecalls.cpp)
add_dependencies(enclave_a key_info_a)
target_link_libraries(enclave_a common)
target_include_directories(enclave_a PRIVATE ${CMAKE_BINARY_DIR}/enc1)
