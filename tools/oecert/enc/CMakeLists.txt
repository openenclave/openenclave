# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_custom_command(
  OUTPUT oecert_t.h oecert_t.c oecert_args.h
  DEPENDS ../oecert.edl edger8r
  COMMAND edger8r --trusted ${CMAKE_CURRENT_SOURCE_DIR}/../oecert.edl
          --search-path ${PROJECT_SOURCE_DIR}/include -DOE_SGX)

# generate the enclave and sign it with the private key
add_enclave(
  TARGET
  oecert_enc
  SOURCES
  enc.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/oecert_t.c
  CONFIG
  enc.conf
  KEY
  ${CMAKE_CURRENT_BINARY_DIR}/../oecert_enc_private.pem)

add_enclave_dependencies(oecert_enc enclave_key_pair)

# Need for the generated file oecert_t.h
enclave_include_directories(oecert_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

enclave_link_libraries(oecert_enc oeenclave oelibc)

# Generate the enclave binary in the the same directory with the oecert binary
set_enclave_properties(oecert_enc PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                       "${CMAKE_CURRENT_BINARY_DIR}/..")

add_custom_target(oecert_enclave_signed DEPENDS oecert_enc.signed
                                                oecert_enc_pubkey.h)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/../oecert_enc.signed
        DESTINATION ${CMAKE_INSTALL_BINDIR})
