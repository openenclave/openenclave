# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../print.edl)

add_custom_command(
  OUTPUT print_u.h print_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(print_host host.cpp print_u.c)

target_include_directories(print_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(print_host oehost)
