# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

if (BUILD_ENCLAVES)
  # Generate a random key pair for enclave signing and output the public key to header file
  # included by the host
  add_custom_command(
    OUTPUT oegenerate_enc_private.pem oegenerate_enc_public.pem
           oegenerate_enc_pubkey.h
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/gen_pubkey_header.sh
    COMMAND openssl genrsa -out oegenerate_enc_private.pem -3 3072
    COMMAND openssl rsa -in oegenerate_enc_private.pem -pubout -out
            oegenerate_enc_public.pem
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/gen_pubkey_header.sh
            oegenerate_enc_pubkey.h oegenerate_enc_public.pem
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

  # Add the custome target against the generated files that both the host and the enclave
  # can enforce the dependency
  add_custom_target(
    enclave_key_pair DEPENDS oegenerate_enc_private.pem
                             oegenerate_enc_public.pem oegenerate_enc_pubkey.h)

  add_subdirectory(host)
  add_subdirectory(enc)
endif ()
