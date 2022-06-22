# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../switchless_atexit_calls.edl)

add_custom_command(
  OUTPUT switchless_atexit_calls_t.h switchless_atexit_calls_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(TARGET sgx_switchless_atexit_calls_enc SOURCES enc.c
            ${CMAKE_CURRENT_BINARY_DIR}/switchless_atexit_calls_t.c)

enclave_include_directories(sgx_switchless_atexit_calls_enc PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})
