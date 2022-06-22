# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../write_with_barrier.edl)

add_custom_command(
  OUTPUT write_with_barrier_t.h write_with_barrier_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(TARGET write_with_barrier_enc SOURCES enc.c
            ${CMAKE_CURRENT_BINARY_DIR}/write_with_barrier_t.c)

enclave_include_directories(write_with_barrier_enc PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})
