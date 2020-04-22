# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set (EDL_FILE ../switchless_nestedcalls.edl)

add_custom_command(
    OUTPUT switchless_nestedcalls_u.h switchless_nestedcalls_u.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r --untrusted ${EDL_FILE} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(switchless_nestedcalls_host host.c switchless_nestedcalls_u.c)

target_include_directories(switchless_nestedcalls_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(switchless_nestedcalls_host oehostapp)
