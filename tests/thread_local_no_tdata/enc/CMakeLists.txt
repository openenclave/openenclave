# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../no_tdata.edl)

add_custom_command(
  OUTPUT no_tdata_t.h no_tdata_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

# Build enclave that has no tdata
add_enclave(
  TARGET
  no_tdata_enc
  UUID
  f60ab316-d838-4014-9909-09c0cf68fe65
  CXX
  SOURCES
  enc.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/no_tdata_t.c)

enclave_include_directories(no_tdata_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
