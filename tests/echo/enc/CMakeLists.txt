# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../echo.edl)

add_custom_command(
  OUTPUT echo_t.h echo_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  echo_enc
  UUID
  71b0822f-42a3-4543-a97c-ca491f76b82c
  SOURCES
  enc.c
  ${CMAKE_CURRENT_BINARY_DIR}/echo_t.c)

enclave_include_directories(echo_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(echo_enc oelibc)
