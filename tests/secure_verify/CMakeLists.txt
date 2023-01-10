# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# This test is disabled for now as it will fail when running on nonSGX steps in the pipeline
# For example, this test would cause pipeline task "Linux nonSGX Verify Quote" to fail
# because this test calls oeutil which can only work on SGX machines

# Even there is BUILD_ENCLAVES option, its not working as expected because its value is
# forced to ON for all builds
# To enable this test, first we should fix BUILD_ENCLAVES

if (BUILD_ENCLAVES)
  # Generate a random key pair for enclave signing and output the public key to header file
  # included by the host
  add_custom_command(
    OUTPUT secure_verify_enc_private.pem secure_verify_enc_public.pem
           secure_verify_enc_pubkey.h
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/gen_pubkey_header.sh
    COMMAND openssl genrsa -out secure_verify_enc_private.pem -3 3072
    COMMAND openssl rsa -in secure_verify_enc_private.pem -pubout -out
            secure_verify_enc_public.pem
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/gen_pubkey_header.sh
            secure_verify_enc_pubkey.h secure_verify_enc_public.pem
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

  # Add the custome target against the generated files that both the host and the enclave
  # can enforce the dependency
  add_custom_target(
    secure_verify_enclave_key_pair
    DEPENDS secure_verify_enc_private.pem secure_verify_enc_public.pem
            secure_verify_enc_pubkey.h)

  # Generate evidence
  set(QUOTE_BINARY quote_ecdsa.bin)
  add_custom_command(
    OUTPUT ${QUOTE_BINARY}
    COMMAND oeutil gen -f SGX_ECDSA -o ${QUOTE_BINARY}
    DEPENDS oeutil oeutil_enclave_signed
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

  add_custom_target(secure_verify_quote_binary DEPENDS ${QUOTE_BINARY})

  add_subdirectory(host)
  add_subdirectory(enc)

  add_test(
    NAME tests/secure_verify.mbedtls
    COMMAND $<TARGET_FILE:secure_verify> secure_verify_enc_mbedtls.signed
            ${QUOTE_BINARY} -f quote
    WORKING_DIRECTORY $<TARGET_FILE_DIR:secure_verify>)
  # ATTN: This currently would fail and root cause is yet to find
  # Possibly caused by incorrectly generated OpenSSL cert
  # add_test(
  #   NAME tests/secure_verify.openssl
  #   COMMAND $<TARGET_FILE:secure_verify> secure_verify_enc_openssl.signed
  #           ${QUOTE_BINARY} -f quote
  #   WORKING_DIRECTORY $<TARGET_FILE_DIR:secure_verify>)

endif ()
