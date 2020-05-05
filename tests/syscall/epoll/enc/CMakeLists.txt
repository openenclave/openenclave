# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../epoll.edl)

add_custom_command(
  OUTPUT epoll_t.h epoll_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(TARGET epoll_enc CXX SOURCES enc.cpp
            ${CMAKE_CURRENT_BINARY_DIR}/epoll_t.c)

enclave_link_libraries(epoll_enc oelibcxx oeenclave oehostepoll oehostsock)
