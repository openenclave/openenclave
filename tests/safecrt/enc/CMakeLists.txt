# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../safecrt.edl)

add_custom_command(
  OUTPUT safecrt_t.h safecrt_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND edger8r --trusted ${EDL_FILE} --search-path
          ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  safecrt_enc
  UUID
  91dc6667-7a33-4bbc-ab3e-ab4fca5215b7
  SOURCES
  ../common/test.cpp
  enc.cpp
  safecrt_t.c)

enclave_include_directories(safecrt_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
