# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../resolver_test.edl)

add_custom_command(
  OUTPUT resolver_test_u.h resolver_test_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR}
    --search-path ${CMAKE_CURRENT_SOURCE_DIR}/../../../include)

add_executable(resolver_host host.c resolver_test_u.c)

target_include_directories(resolver_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(resolver_host oehost)
