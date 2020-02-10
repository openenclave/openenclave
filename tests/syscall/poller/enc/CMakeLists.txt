# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set (EDL_FILE ../poller.edl)

add_custom_command(
    OUTPUT poller_t.h poller_t.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r --trusted ${EDL_FILE} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(poller_enc
    enc.cpp ../client.cpp ../server.cpp ../poller.cpp poller_t.c)

maybe_build_using_clangw(poller_enc)

if (CODE_COVERAGE_TEST)
    target_link_libraries(poller_enc gcda oehostfs)
endif()
target_link_libraries(poller_enc oelibcxx oeenclave oehostepoll oehostsock)
