# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../mixed.edl)

add_custom_command(
  OUTPUT mixed_t.h mixed_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  mixed_c_cpp_enc
  UUID
  952c55c8-59f3-47a0-814c-ae3276a9808f
  CXX
  SOURCES
  enc.cpp
  foo.c
  ${CMAKE_CURRENT_BINARY_DIR}/mixed_t.c)
enclave_include_directories(mixed_c_cpp_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
