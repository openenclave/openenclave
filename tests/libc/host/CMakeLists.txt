# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../libc.edl)

add_custom_command(
  OUTPUT libc_u.h libc_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(libc_host host.cpp libc_u.c)

target_include_directories(libc_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                                             ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(libc_host oehost)
