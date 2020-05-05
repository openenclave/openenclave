# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../test_dup.edl)

add_custom_command(
  OUTPUT test_dup_u.h test_dup_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR}
    --search-path ${CMAKE_CURRENT_SOURCE_DIR}/../../../device/edl)

add_executable(dup_host host.c test_dup_u.c)

target_include_directories(dup_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(dup_host oehost)
