# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../backtrace.edl)

add_custom_command(
  OUTPUT backtrace_u.h backtrace_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(sgx_backtrace_host host.c backtrace_u.c)

target_include_directories(
  sgx_backtrace_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                             ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(sgx_backtrace_host oehost)
