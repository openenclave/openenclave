# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../child_thread.edl)

add_custom_command(
  OUTPUT child_thread_u.h child_thread_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(child_thread_host host.cpp child_thread_u.c)

target_include_directories(child_thread_host
                           PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(child_thread_host oehost)
