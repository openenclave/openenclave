# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../abortStatus.edl)

add_custom_command(
  OUTPUT abortStatus_t.h abortStatus_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND edger8r --trusted ${EDL_FILE} --search-path
          ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  abortStatus_enc
  UUID
  c55a7e2a-b857-4518-98df-4d294d0ab14d
  CXX
  SOURCES
  enc.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/abortStatus_t.c)

enclave_compile_features(abortStatus_enc PRIVATE cxx_generalized_initializers)

enclave_include_directories(abortStatus_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                            ${CMAKE_CURRENT_SOURCE_DIR})
