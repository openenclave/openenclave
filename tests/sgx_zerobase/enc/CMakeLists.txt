# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../sgx_zerobase.edl)

add_custom_command(
  OUTPUT sgx_zerobase_t.h sgx_zerobase_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(TARGET sgx_zerobase_enc SOURCES enc.cpp
            ${CMAKE_CURRENT_BINARY_DIR}/sgx_zerobase_t.c)

enclave_include_directories(
  sgx_zerobase_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR})
