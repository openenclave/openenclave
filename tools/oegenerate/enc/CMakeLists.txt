# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_custom_command(
  OUTPUT oegenerate_t.h oegenerate_t.c oegenerate_args.h
  DEPENDS ../oegenerate.edl edger8r
  COMMAND edger8r --trusted ${CMAKE_CURRENT_SOURCE_DIR}/../oegenerate.edl
          --search-path ${PROJECT_SOURCE_DIR}/include -DOE_SGX)

# generate the enclave and sign it with the private key
add_enclave(
  TARGET
  oegenerate_enc
  SOURCES
  enc.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/oegenerate_t.c
  CONFIG
  enc.conf
  KEY
  ${CMAKE_CURRENT_BINARY_DIR}/../oegenerate_enc_private.pem)

add_enclave_dependencies(oegenerate_enc enclave_key_pair)

# Need for the generated file oegenerate_t.h
enclave_include_directories(oegenerate_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

enclave_link_libraries(oegenerate_enc oeenclave oelibc)

# Generate the enclave binary in the the same directory with the oegenerate binary
set_enclave_properties(oegenerate_enc PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                       ${OE_BINDIR})

add_custom_target(oegenerate_enclave_signed DEPENDS oegenerate_enc.signed
                                                    oegenerate_enc_pubkey.h)

install(FILES ${OE_BINDIR}/oegenerate_enc.signed
        DESTINATION ${CMAKE_INSTALL_BINDIR})
