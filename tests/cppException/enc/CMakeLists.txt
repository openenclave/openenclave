# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../cppException.edl)

add_custom_command(
  OUTPUT cppException_t.h cppException_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  cppException_enc
  UUID
  fdabde1a-a03a-4850-a07d-633eea54af92
  CXX
  SOURCES
  enc.cpp
  cppException.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/cppException_t.c)

enclave_compile_features(cppException_enc PRIVATE cxx_generalized_initializers)

set(NO_SPECTRE_MITIGATION_FLAGS -mno-speculative-load-hardening)
check_c_compiler_flag("${NO_SPECTRE_MITIGATION_FLAGS}"
                      SPECTRE_MITIGATION_C_FLAGS_SUPPORTED)
check_cxx_compiler_flag("${NO_SPECTRE_MITIGATION_FLAGS}"
                        SPECTRE_MITIGATION_CXX_FLAGS_SUPPORTED)
if (SPECTRE_MITIGATION_C_FLAGS_SUPPORTED
    AND SPECTRE_MITIGATION_CXX_FLAGS_SUPPORTED)
  enclave_compile_options(cppException_enc PRIVATE
                          ${NO_SPECTRE_MITIGATION_FLAGS})
endif ()

enclave_include_directories(
  cppException_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR})
