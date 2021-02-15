# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../custom_claims.edl)

add_custom_command(
  OUTPUT custom_claims_t.h custom_claims_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  custom_claims_enc
  UUID
  8479af9f-2ee8-4ccd-8336-8696dde57a11
  SOURCES
  enc.c
  ../test_common/tests.c
  ${CMAKE_CURRENT_BINARY_DIR}/custom_claims_t.c)

enclave_include_directories(custom_claims_enc PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(custom_claims_enc oelibc)
