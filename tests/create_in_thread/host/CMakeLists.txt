# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set (EDL_FILE ../create_in_thread.edl)

add_custom_command(
    OUTPUT create_in_thread_u.h create_in_thread_u.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r --untrusted ${EDL_FILE} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(create_in_thread_host host.cpp create_in_thread_u.c)

target_include_directories(create_in_thread_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(create_in_thread_host oehostapp)
