# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Generate header with public key of enclave B (2)
add_custom_command(
  OUTPUT enclave_b_pubkey.h
  DEPENDS public_key_b ${CMAKE_SOURCE_DIR}/gen_pubkey_header.sh
  COMMAND ${CMAKE_SOURCE_DIR}/gen_pubkey_header.sh enclave_b_pubkey.h
          ${CMAKE_BINARY_DIR}/enclave_b/public_b.pem)

add_executable(enclave_a ecalls.cpp
                         ${CMAKE_CURRENT_BINARY_DIR}/enclave_b_pubkey.h)

if (WIN32)
  maybe_build_using_clangw(enclave_a)
endif ()

target_include_directories(enclave_a PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(enclave_a common)

# Generate key A
add_custom_command(
  OUTPUT private_a.pem public_a.pem
  COMMAND openssl genrsa -out private_a.pem -3 3072
  COMMAND openssl rsa -in private_a.pem -pubout -out public_a.pem)

add_custom_target(public_key_a DEPENDS public_a.pem)

# Sign enclave A with key A
add_custom_command(
  OUTPUT enclave_a.signed
  DEPENDS enclave_a enc.conf private_a.pem
  COMMAND openenclave::oesign sign -e $<TARGET_FILE:enclave_a> -c
          ${CMAKE_CURRENT_SOURCE_DIR}/enc.conf -k private_a.pem)

add_custom_target(enclave_a_signed ALL DEPENDS enclave_a.signed)
