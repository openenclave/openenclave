# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../debug_mode.edl)

add_custom_command(
  OUTPUT debug_mode_t.h debug_mode_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  no_debug_enc_unsigned
  UUID
  f10dc769-9849-4141-9dd5-12b7f78a56fd
  SOURCES
  enc.c
  props.c
  ${CMAKE_CURRENT_BINARY_DIR}/debug_mode_t.c)

add_enclave(
  TARGET
  no_debug_enc
  UUID
  e90548a8-3146-4d09-86e3-ea2bc56b6543
  CONFIG
  sign.conf
  SOURCES
  enc.c
  props.c
  ${CMAKE_CURRENT_BINARY_DIR}/debug_mode_t.c)

add_enclave(
  TARGET
  debug_enc
  UUID
  9c99c483-93de-41ef-9d8b-abb290a00f41
  CONFIG
  sign-debug.conf
  SOURCES
  enc.c
  props-debug.c
  ${CMAKE_CURRENT_BINARY_DIR}/debug_mode_t.c)

add_enclave(
  TARGET
  debug_enc_unsigned
  UUID
  6e214c32-51ff-4bf4-ab81-e164bc67c154
  SOURCES
  enc.c
  props-debug.c
  ${CMAKE_CURRENT_BINARY_DIR}/debug_mode_t.c)

enclave_include_directories(
  no_debug_enc_unsigned PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR})
enclave_link_libraries(no_debug_enc_unsigned oelibc)

enclave_include_directories(no_debug_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                            ${CMAKE_CURRENT_SOURCE_DIR})
enclave_link_libraries(no_debug_enc oelibc)

enclave_include_directories(debug_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                            ${CMAKE_CURRENT_SOURCE_DIR})
enclave_link_libraries(debug_enc oelibc)

enclave_include_directories(
  debug_enc_unsigned PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR})
enclave_link_libraries(debug_enc_unsigned oelibc)
