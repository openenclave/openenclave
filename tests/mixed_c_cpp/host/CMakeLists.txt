# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../mixed.edl)

add_custom_command(
  OUTPUT mixed_u.h mixed_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(mixed_c_cpp_host host.cpp mixed_u.c)

target_include_directories(mixed_c_cpp_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(mixed_c_cpp_host oehost)
