# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../debug_malloc.edl)

add_custom_command(
  OUTPUT debug_malloc_u.h debug_malloc_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(debug_malloc_host host.c debug_malloc_u.c)

target_include_directories(debug_malloc_host
                           PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(debug_malloc_host oehost)
