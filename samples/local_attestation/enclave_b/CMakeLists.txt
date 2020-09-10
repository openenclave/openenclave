# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Generate header with public key of enclave A
add_custom_command(
  OUTPUT enclave_a_pubkey.h
  DEPENDS public_key_a ${CMAKE_SOURCE_DIR}/gen_pubkey_header.sh
  COMMAND ${CMAKE_SOURCE_DIR}/gen_pubkey_header.sh enclave_a_pubkey.h
          ${CMAKE_BINARY_DIR}/enclave_a/public_a.pem)

add_executable(enclave_b ecalls.cpp
                         ${CMAKE_CURRENT_BINARY_DIR}/enclave_a_pubkey.h)

if (WIN32)
  maybe_build_using_clangw(enclave_b)
endif ()

target_include_directories(enclave_b PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(enclave_b common)

# Generate key B
add_custom_command(
  OUTPUT private_b.pem public_b.pem
  COMMAND openssl genrsa -out private_b.pem -3 3072
  COMMAND openssl rsa -in private_b.pem -pubout -out public_b.pem)

add_custom_target(public_key_b DEPENDS public_b.pem)

# Sign enclave B with key B
add_custom_command(
  OUTPUT enclave_b.signed
  DEPENDS enclave_b enc.conf private_b.pem
  COMMAND openenclave::oesign sign -e $<TARGET_FILE:enclave_b> -c
          ${CMAKE_CURRENT_SOURCE_DIR}/enc.conf -k private_b.pem)

add_custom_target(enclave_b_signed ALL DEPENDS enclave_b.signed)
