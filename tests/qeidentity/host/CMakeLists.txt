# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../tests.edl)

add_custom_command(
  OUTPUT tests_u.h tests_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND edger8r --untrusted ${EDL_FILE} --search-path
          ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(qeidentity_host host.cpp qeidentifyinfo.cpp tests_u.c)

if (HAS_QUOTE_PROVIDER)
  target_compile_definitions(qeidentity_host PRIVATE OE_LINK_SGX_DCAP_QL)
endif ()

add_custom_command(
  TARGET qeidentity_host
  COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/../data
          ${CMAKE_CURRENT_BINARY_DIR}/../data
  COMMAND
    ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/../data_v2
    ${CMAKE_CURRENT_BINARY_DIR}/../data_v2)

target_include_directories(
  qeidentity_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                          ${CMAKE_CURRENT_SOURCE_DIR}/../common)
target_link_libraries(qeidentity_host oehost)
