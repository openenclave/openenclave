# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../edl/edl_opt_out.edl)

add_custom_command(
  OUTPUT edl_opt_out_t.h edl_opt_out_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

set(PLATFORM_EDL_FILE ../edl/header.edl)
add_custom_command(
  OUTPUT header_t.h
  DEPENDS ${PLATFORM_EDL_FILE} edger8r
  COMMAND
    edger8r --header-only --trusted ${PLATFORM_EDL_FILE} --search-path
    ${PROJECT_SOURCE_DIR}/include ${DEFINE_OE_SGX} --search-path
    ${CMAKE_CURRENT_SOURCE_DIR})
add_custom_target(trusted_header DEPENDS header_t.h)

add_enclave(
  TARGET
  edl_opt_out_enc
  UUID
  892e7f65-5da1-45d0-8209-53795ce5be8f
  CRYPTO_LIB
  OpenSSL
  SOURCES
  enc.c
  ${CMAKE_CURRENT_BINARY_DIR}/edl_opt_out_t.c)

add_enclave_dependencies(edl_opt_out_enc trusted_header)

enclave_include_directories(edl_opt_out_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(edl_opt_out_enc oelibc)
