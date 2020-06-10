# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../ecall_ocall.edl)

add_custom_command(
  OUTPUT ecall_ocall_t.h ecall_ocall_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  ecall_ocall_enc
  UUID
  61610af2-7821-4a0a-b47a-ae036abfd69b
  CXX
  SOURCES
  enc.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/ecall_ocall_t.c)
enclave_compile_features(ecall_ocall_enc PRIVATE cxx_auto_type)

enclave_include_directories(ecall_ocall_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
