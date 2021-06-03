# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_custom_command(
  OUTPUT oeutil_t.h oeutil_t.c oeutil_args.h
  DEPENDS ../oeutil.edl edger8r
  COMMAND edger8r --trusted ${CMAKE_CURRENT_SOURCE_DIR}/../oeutil.edl
          --search-path ${PROJECT_SOURCE_DIR}/include -DOE_SGX)

# generate the enclave and sign it with the private key
add_enclave(
  TARGET
  oeutil_enc
  SOURCES
  generate_evidence_enc.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/oeutil_t.c
  CONFIG
  enc.conf
  KEY
  ${CMAKE_CURRENT_BINARY_DIR}/../oeutil_enc_private.pem)

add_enclave_dependencies(oeutil_enc enclave_key_pair)

# Need for the generated file oeutil_t.h
enclave_include_directories(oeutil_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

enclave_link_libraries(oeutil_enc oeenclave oelibc)

# Generate the enclave binary in the the same directory with the oeutil binary
set_enclave_properties(oeutil_enc PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                       ${OE_BINDIR})

add_custom_target(oeutil_enclave_signed DEPENDS oeutil_enc.signed
                                                oeutil_enc_pubkey.h)

install(FILES ${OE_BINDIR}/oeutil_enc.signed
        DESTINATION ${CMAKE_INSTALL_BINDIR})
