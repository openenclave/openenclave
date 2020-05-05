# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../c99_compliant.edl)

add_custom_command(
  OUTPUT c99_compliant_t.h c99_compliant_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  c99_compliant_enc
  UUID
  b843807a-e05c-423c-bcfb-1062cadb482f
  SOURCES
  enc.c
  ${CMAKE_CURRENT_BINARY_DIR}/c99_compliant_t.c)

set_enclave_property(TARGET c99_compliant_enc PROPERTY C_STANDARD 99)

enclave_include_directories(c99_compliant_enc PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(c99_compliant_enc oelibc)
