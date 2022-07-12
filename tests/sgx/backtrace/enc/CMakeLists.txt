# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../backtrace.edl)

add_custom_command(
  OUTPUT backtrace_t.h backtrace_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(TARGET sgx_backtrace_enc SOURCES enc.c config_pfgp.c
            ${CMAKE_CURRENT_BINARY_DIR}/backtrace_t.c)

enclave_include_directories(
  sgx_backtrace_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(TARGET sgx_backtrace_no_pfgp_enc SOURCES enc.c config_no_pfgp.c
            ${CMAKE_CURRENT_BINARY_DIR}/backtrace_t.c)

enclave_include_directories(
  sgx_backtrace_no_pfgp_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR})
