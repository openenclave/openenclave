# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../tls.edl)

add_custom_command(
  OUTPUT tls_t.h tls_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  tls_enc
  UUID
  6cc330ff-c8cf-49d4-92ef-e1674794f820
  SOURCES
  enc.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/tls_t.c)

enclave_include_directories(tls_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(tls_enc oeenclave oelibc)
