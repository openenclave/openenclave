# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../db_test.edl)

add_custom_command(
  OUTPUT db_test_u.h db_test_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(db_test_host host.c contract.c db_test_u.c)

target_include_directories(db_test_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(db_test_host oehost)
