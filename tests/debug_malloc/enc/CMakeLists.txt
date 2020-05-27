# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../debug_malloc.edl)

add_custom_command(
  OUTPUT debug_malloc_t.h debug_malloc_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  debug_malloc_enc
  UUID
  29070d0f-11e3-4612-aef7-7456924eb7ac
  SOURCES
  enc.c
  ${CMAKE_CURRENT_BINARY_DIR}/debug_malloc_t.c)

enclave_include_directories(debug_malloc_enc PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(debug_malloc_enc oelibc)
