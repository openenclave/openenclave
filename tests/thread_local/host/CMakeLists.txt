# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../thread_local.edl)

add_custom_command(
  OUTPUT thread_local_u.h thread_local_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(thread_local_host host.cpp thread_local_u.c)

target_include_directories(thread_local_host
                           PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_compile_options(thread_local_host
                       PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-std=c++11>)
target_link_libraries(thread_local_host oehost)
