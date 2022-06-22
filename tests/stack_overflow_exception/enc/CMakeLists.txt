# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../stack_overflow_exception.edl)

add_custom_command(
  OUTPUT stack_overflow_exception_t.h stack_overflow_exception_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  sgx_stack_overflow_exception_enc
  CONFIG
  sign.conf
  SOURCES
  enc.c
  ${CMAKE_CURRENT_BINARY_DIR}/stack_overflow_exception_t.c)

add_enclave(TARGET sgx_stack_overflow_exception_enc_unsigned SOURCES enc.c
            ${CMAKE_CURRENT_BINARY_DIR}/stack_overflow_exception_t.c)

enclave_include_directories(sgx_stack_overflow_exception_enc PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})

enclave_include_directories(sgx_stack_overflow_exception_enc_unsigned PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})
