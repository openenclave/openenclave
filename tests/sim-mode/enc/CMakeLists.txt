# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../sim_mode.edl)

add_custom_command(
  OUTPUT sim_mode_t.h sim_mode_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  enc_unsigned
  UUID
  6771bad2-805a-11ea-bc55-0242ac130003
  SOURCES
  enc.c
  props.c
  ${CMAKE_CURRENT_BINARY_DIR}/sim_mode_t.c)

add_enclave(
  TARGET
  enc
  UUID
  82fc6d38-805a-11ea-bc55-0242ac130003
  CONFIG
  sign.conf
  SOURCES
  enc.c
  props.c
  ${CMAKE_CURRENT_BINARY_DIR}/sim_mode_t.c)

enclave_include_directories(enc_unsigned PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                            ${CMAKE_CURRENT_SOURCE_DIR})
enclave_link_libraries(enc_unsigned oelibc)

enclave_include_directories(enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                            ${CMAKE_CURRENT_SOURCE_DIR})
enclave_link_libraries(enc oelibc)
