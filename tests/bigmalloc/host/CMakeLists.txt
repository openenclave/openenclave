# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../bigmalloc.edl)

add_custom_command(
  OUTPUT bigmalloc_u.h bigmalloc_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND edger8r --untrusted ${EDL_FILE} --search-path
          ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(bigmalloc_host host.c bigmalloc_u.c)

target_include_directories(bigmalloc_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(bigmalloc_host oehost)
