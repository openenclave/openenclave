# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../print.edl)

add_custom_command(
  OUTPUT print_t.h print_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  print_enc
  UUID
  58f3e795-00c3-45e0-9435-3e6fcf734acc
  SOURCES
  enc.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/print_t.c)

enclave_compile_options(
  print_enc PRIVATE -fno-builtin-strcpy -fno-builtin-strcat -fno-builtin-memcpy
  -fno-builtin-memset)

if (CMAKE_C_COMPILER_ID MATCHES GNU)
  enclave_compile_options(print_enc PRIVATE -Wno-error=unused-but-set-variable)
endif ()

enclave_include_directories(print_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(print_enc oelibc)
