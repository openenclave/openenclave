# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../backtrace.edl)

add_custom_command(
  OUTPUT backtrace_t.h backtrace_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  backtrace_enc
  UUID
  c21d0c84-a32b-430a-ad9a-7bf8b47eff0c
  CXX
  SOURCES
  enc.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/backtrace_t.c)

enclave_link_libraries(backtrace_enc oelibc)

enclave_include_directories(backtrace_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                            ${CMAKE_CURRENT_SOURCE_DIR})
