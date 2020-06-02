# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../ecall.edl)

add_custom_command(
  OUTPUT ecall_u.h ecall_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(ecall_host host.cpp ecall_u.c)

target_include_directories(ecall_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(ecall_host oehost)
