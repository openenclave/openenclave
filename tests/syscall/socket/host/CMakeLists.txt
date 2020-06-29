# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../socket_test.edl)

add_custom_command(
  OUTPUT socket_test_u.h socket_test_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR} --search-path
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../include)

add_executable(socket_host host.c socket_test_u.c)

target_include_directories(socket_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(socket_host oehost)
