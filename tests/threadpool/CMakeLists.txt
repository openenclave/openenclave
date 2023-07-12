# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

if (BUILD_ENCLAVES)
  set(PROJ "threadpool")

  string(CONCAT gen_pubkey_header_command
                "${CMAKE_CURRENT_SOURCE_DIR}/gen_pubkey_header.sh "
                "${PROJ}_enc_pubkey.h ${PROJ}_enc_public.pem")

  # Generate a random key pair for enclave signing and output the public key to header file
  # included by the host
  add_custom_command(
    OUTPUT ${PROJ}_enc_private.pem ${PROJ}_enc_public.pem
    COMMAND openssl genrsa -out ${PROJ}_enc_private.pem -3 3072
    COMMAND openssl rsa -in ${PROJ}_enc_private.pem -pubout -out
            ${PROJ}_enc_public.pem
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

  add_custom_command(
    OUTPUT ${PROJ}_enc_pubkey.h
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/gen_pubkey_header.sh
            ${PROJ}_enc_private.pem ${PROJ}_enc_public.pem
    COMMAND ${OE_BASH} -c ${gen_pubkey_header_command}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

  # Add the custome target against the generated files that both the host and the enclave
  # can enforce the dependency
  add_custom_target(
    ${PROJ}_enclave_key_pair
    DEPENDS ${PROJ}_enc_private.pem ${PROJ}_enc_public.pem ${PROJ}_enc_pubkey.h)

  add_subdirectory(host)
  add_subdirectory(enc)

  add_enclave_test(tests/${PROJ} ${PROJ} ${PROJ}_enc_signed)
  set_enclave_tests_properties(tests/${PROJ} PROPERTIES SKIP_RETURN_CODE 2)

endif ()
