# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../ecall_ocall.edl)

add_custom_command(
  OUTPUT ecall_ocall_u.h ecall_ocall_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(ecall_ocall_host host.cpp ecall_ocall_u.c)

target_include_directories(ecall_ocall_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(ecall_ocall_host oehost)
