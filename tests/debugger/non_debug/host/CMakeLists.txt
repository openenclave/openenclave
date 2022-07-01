# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../non_debug.edl)

add_custom_command(
  OUTPUT non_debug_u.h non_debug_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(non_debug_host host.c non_debug_u.c)

target_include_directories(non_debug_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(non_debug_host oehost)
