# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../write_with_barrier.edl)

add_custom_command(
  OUTPUT write_with_barrier_u.h write_with_barrier_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(write_with_barrier_host host.c write_with_barrier_u.c)

target_include_directories(write_with_barrier_host
                           PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(write_with_barrier_host oehost)
