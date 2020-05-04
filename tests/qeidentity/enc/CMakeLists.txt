# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../tests.edl)

add_custom_command(
  OUTPUT tests_t.h tests_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND edger8r --trusted ${EDL_FILE} --search-path
          ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  qeidentity_enc
  UUID
  a656f3b1-d319-4692-bcd6-a2f50d9fb1e5
  SOURCES
  enc.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/tests_t.c)

if (HAS_QUOTE_PROVIDER)
  enclave_compile_definitions(qeidentity_enc PRIVATE HAS_QUOTE_PROVIDER)
endif ()

enclave_include_directories(qeidentity_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                            ${CMAKE_CURRENT_SOURCE_DIR}/../common)
enclave_link_libraries(qeidentity_enc oelibc)
