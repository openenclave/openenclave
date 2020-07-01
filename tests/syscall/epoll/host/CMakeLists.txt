# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Use full path to edl file to avoid ${PLATFORM_EDL_DIR}/../epoll.edl
# from getting picked up instead.
set(EDL_FILE ${CMAKE_CURRENT_SOURCE_DIR}/../epoll.edl)

add_custom_command(
  OUTPUT epoll_u.h epoll_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND edger8r --untrusted ${EDL_FILE} --search-path
          ${PROJECT_SOURCE_DIR}/include ${DEFINE_OE_SGX})

add_executable(epoll_host host.cpp epoll_u.c)

target_include_directories(epoll_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(epoll_host oehost)
