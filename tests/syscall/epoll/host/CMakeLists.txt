# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../epoll.edl)

add_custom_command(
  OUTPUT epoll_u.h epoll_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND edger8r --untrusted ${EDL_FILE} --search-path
          ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(epoll_host host.cpp epoll_u.c)

target_include_directories(epoll_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(epoll_host oehost)
