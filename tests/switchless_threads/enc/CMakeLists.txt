# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../switchless_threads.edl)

add_custom_command(
  OUTPUT switchless_threads_t.h switchless_threads_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  switchless_threads_enc
  UUID
  6e818629-0ce7-46cd-822a-6c7e081fc68b
  SOURCES
  enc.c
  ${CMAKE_CURRENT_BINARY_DIR}/switchless_threads_t.c)

enclave_include_directories(switchless_threads_enc PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(switchless_threads_enc oelibc)
