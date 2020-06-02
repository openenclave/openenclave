# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../argv.edl)

add_custom_command(
  OUTPUT argv_t.h argv_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  argv_enc
  UUID
  c7d594f3-2d7a-4056-8d38-e0531926c676
  SOURCES
  enc.c
  argv_t.c)

enclave_include_directories(argv_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

enclave_link_libraries(argv_enc oelibc)
