# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../hostcalls.edl)

add_custom_command(
  OUTPUT hostcalls_t.h hostcalls_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  hostcalls_enc
  UUID
  60814a64-61e9-4fd9-9159-e158d73f6a2e
  SOURCES
  enc.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/hostcalls_t.c)

enclave_include_directories(hostcalls_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                            ${CMAKE_CURRENT_SOURCE_DIR})
enclave_link_libraries(hostcalls_enc oelibc)
