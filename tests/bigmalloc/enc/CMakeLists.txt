# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../bigmalloc.edl)

add_custom_command(
  OUTPUT bigmalloc_t.h bigmalloc_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

# Unlike other tests, this test explicitly requires a signed enclave
# to test if a big enclave can be signed.
add_enclave(
  TARGET
  bigmalloc_enc
  UUID
  e4a54387-25fe-4b8f-b1ba-579eb525144f
  CONFIG
  sign.conf
  SOURCES
  enc.c
  ${CMAKE_CURRENT_BINARY_DIR}/bigmalloc_t.c)

enclave_include_directories(bigmalloc_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(bigmalloc_enc oelibc)
