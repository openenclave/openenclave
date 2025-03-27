# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../consolefs.edl)

add_custom_command(
  OUTPUT consolefs_u.h consolefs_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(consolefs_host host.c consolefs_u.c)

target_include_directories(consolefs_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(consolefs_host oehost)
