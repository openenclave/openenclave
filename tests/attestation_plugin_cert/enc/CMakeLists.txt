# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../tls.edl)

add_custom_command(
  OUTPUT tls_t.h tls_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  tls_cert_enc
  UUID
  06999b6d-4132-461a-94da-f3972f68f301
  SOURCES
  enc.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/tls_t.c)

enclave_include_directories(tls_cert_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(tls_cert_enc oeenclave oelibc)
