# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../sgxextra.edl)

add_custom_command(
  OUTPUT sgxextra_t.h sgxextra_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  sgxextra_enc
  UUID
  e5c9ed77-a22d-4998-ab76-ac1c0cd08d45
  SOURCES
  enc.c
  ${CMAKE_CURRENT_BINARY_DIR}/sgxextra_t.c)

enclave_include_directories(sgxextra_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

enclave_link_libraries(sgxextra_enc oelibc)
