# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../compiler_rt.edl)

add_custom_command(
  OUTPUT compiler_rt_u.h compiler_rt_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(compiler_rt_host host.c compiler_rt_u.c)

target_include_directories(compiler_rt_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(compiler_rt_host oehost)
