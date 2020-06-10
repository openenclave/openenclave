# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../thread.edl)

add_custom_command(
  OUTPUT thread_u.h thread_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(thread_host host.cpp rwlocks_test_host.cpp errno_test_host.cpp
                           thread_u.c)

target_include_directories(thread_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(thread_host oehost)
