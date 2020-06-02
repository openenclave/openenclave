# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../snmalloc.edl)

add_custom_command(
  OUTPUT snmalloc_u.h snmalloc_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(snmalloc_host host.c snmalloc_u.c)

target_include_directories(snmalloc_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(snmalloc_host oehost)
