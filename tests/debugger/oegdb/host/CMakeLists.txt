# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../oe_gdb_test.edl)

add_custom_command(
  OUTPUT oe_gdb_test_u.h oe_gdb_test_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(oe_gdb_test_host host.c contract.c oe_gdb_test_u.c)

target_include_directories(oe_gdb_test_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(oe_gdb_test_host oehost)
