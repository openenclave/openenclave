# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../test.edl)

add_custom_command(
  OUTPUT test_u.h test_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(sqlite_host host.c test_u.c)

target_include_directories(sqlite_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(sqlite_host oehost)
