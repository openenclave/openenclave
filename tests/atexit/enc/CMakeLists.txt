# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../atexit.edl)

add_custom_command(
  OUTPUT atexit_t.h atexit_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  atexit_enc
  UUID
  faa3fd16-70ff-11ea-bc55-0242ac130003
  SOURCES
  enc.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/atexit_t.c)

enclave_include_directories(atexit_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(atexit_enc oelibc)
