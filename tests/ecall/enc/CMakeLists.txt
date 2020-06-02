# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../ecall.edl)

add_custom_command(
  OUTPUT ecall_t.h ecall_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  ecall_enc
  UUID
  985c1ef2-d780-4092-af68-0258d0cc691d
  SOURCES
  enc.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/ecall_t.c)

enclave_include_directories(ecall_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                            ${CMAKE_CURRENT_SOURCE_DIR})
enclave_link_libraries(ecall_enc oelibc)
