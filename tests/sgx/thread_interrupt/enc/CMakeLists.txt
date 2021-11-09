# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../thread_interrupt.edl)

add_custom_command(
  OUTPUT thread_interrupt_t.h thread_interrupt_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(TARGET sgx_thread_interrupt_enc SOURCES enc.c
            ${CMAKE_CURRENT_BINARY_DIR}/thread_interrupt_t.c)

enclave_include_directories(sgx_thread_interrupt_enc PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})
