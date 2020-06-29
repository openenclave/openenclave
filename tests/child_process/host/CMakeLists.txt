# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../child_process.edl)

add_custom_command(
  OUTPUT child_process_u.h child_process_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(child_process_host host.cpp child_process_u.c)

target_include_directories(child_process_host
                           PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(child_process_host oehost)
