# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_custom_command(OUTPUT enc1/private.pem
                   COMMAND openssl genrsa -out enc1/private.pem -3 3072)
set(PRIVATE_KEY_ENC1 ${CMAKE_CURRENT_BINARY_DIR}/enc1/private.pem)

add_custom_command(OUTPUT enc1/public.pem
                   COMMAND openssl rsa -in enc1/private.pem -out enc1/public.pem -pubout
           DEPENDS ${PRIVATE_KEY_ENC1})
set(PUBLIC_KEY_ENC1 ${CMAKE_CURRENT_BINARY_DIR}/enc1/public.pem)

add_custom_command(OUTPUT enc2/private.pem
                   COMMAND openssl genrsa -out enc2/private.pem -3 3072)
set(PRIVATE_KEY_ENC2 ${CMAKE_CURRENT_BINARY_DIR}/enc2/private.pem)

add_custom_command(OUTPUT enc2/public.pem
                   COMMAND openssl rsa -in enc2/private.pem -out enc2/public.pem -pubout
                   DEPENDS ${PRIVATE_KEY_ENC2})
set(PUBLIC_KEY_ENC2 ${CMAKE_CURRENT_BINARY_DIR}/enc2/public.pem)

add_custom_command(OUTPUT enc1/enc2_pubkey.h
                   COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/gen_pubkey_header.sh enc1/enc2_pubkey.h ${PUBLIC_KEY_ENC2}
           DEPENDS ${PUBLIC_KEY_ENC2})
set(ENC2_PUB_H ${CMAKE_CURRENT_BINARY_DIR}/enc1/enc2_pubkey.h)

add_custom_command(OUTPUT enc2/enc1_pubkey.h
                   COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/gen_pubkey_header.sh enc2/enc1_pubkey.h ${PUBLIC_KEY_ENC1}
                   DEPENDS ${PUBLIC_KEY_ENC1})
set(ENC1_PUB_H ${CMAKE_CURRENT_BINARY_DIR}/enc2/enc1_pubkey.h)

add_custom_target(local_attestation ALL DEPENDS ${ENC2_PUB_H} ${ENC1_PUB_H})

add_subdirectory(host)

if (BUILD_ENCLAVES)
  add_subdirectory(enc1)
  add_subdirectory(enc2)
endif ()

add_test(samples/local_attestation ${CMAKE_CURRENT_BINARY_DIR}/host/local_attestation_host ${CMAKE_CURRENT_BINARY_DIR}/enc1/local_attestation_enc1.signed ${CMAKE_CURRENT_BINARY_DIR}/enc2/local_attestation_enc2.signed)
set_tests_properties(samples/local_attestation PROPERTIES SKIP_RETURN_CODE 1)
