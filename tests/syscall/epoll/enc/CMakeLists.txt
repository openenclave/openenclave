# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set (EDL_FILE ../epoll.edl)

add_custom_command(
    OUTPUT epoll_t.h epoll_t.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r --trusted ${EDL_FILE} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(epoll_enc enc.cpp epoll_t.c)

maybe_build_using_clangw(epoll_enc)

if (CODE_COVERAGE_TEST)
    target_link_libraries(epoll_enc gcda oehostfs)
endif()
target_link_libraries(epoll_enc oelibcxx oeenclave oehostepoll oehostsock)
