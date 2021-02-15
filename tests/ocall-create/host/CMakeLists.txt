# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../ocall_create.edl)

add_custom_command(
  OUTPUT ocall_create_u.h ocall_create_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(ocall_create_host host.c ocall_create_u.c)

target_include_directories(ocall_create_host
                           PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(ocall_create_host oehost)
