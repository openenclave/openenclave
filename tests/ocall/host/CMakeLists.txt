# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../ocall.edl)

add_custom_command(
  OUTPUT ocall_u.h ocall_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND edger8r --untrusted ${EDL_FILE} --search-path
          ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(ocall_host host.cpp ocall_u.c)

target_include_directories(ocall_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(ocall_host oehost)
