# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../child_process.edl)

add_custom_command(
  OUTPUT child_process_t.h child_process_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND edger8r --trusted ${EDL_FILE} --search-path
          ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  child_process_enc
  UUID
  5b866d98-9e2c-4254-8e09-b6907a02733c
  SOURCES
  enc.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/child_process_t.c)

enclave_include_directories(child_process_enc PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(child_process_enc oelibc)
