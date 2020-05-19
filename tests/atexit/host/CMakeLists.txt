# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../atexit.edl)

add_custom_command(
  OUTPUT atexit_u.h atexit_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND edger8r --untrusted ${EDL_FILE} --search-path
          ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(atexit_host host.cpp atexit_u.c)

target_include_directories(atexit_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(atexit_host oehost)
