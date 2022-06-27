# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../thread_interrupt.edl)

add_custom_command(
  OUTPUT thread_interrupt_u.h thread_interrupt_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(thread_interrupt_host host.c thread_interrupt_u.c)

target_include_directories(thread_interrupt_host
                           PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(thread_interrupt_host oehost)
