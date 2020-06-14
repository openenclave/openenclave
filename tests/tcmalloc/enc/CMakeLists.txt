# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../tcmalloc.edl)

add_custom_command(
  OUTPUT tcmalloc_t.h tcmalloc_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  tcmalloc_enc
  UUID
  e024b61f-8599-499d-bd83-b4b9da9dd389
  SOURCES
  enc.c
  ${CMAKE_CURRENT_BINARY_DIR}/tcmalloc_t.c)

enclave_include_directories(tcmalloc_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(tcmalloc_enc oetcmalloc oelibcxx oelibc)
