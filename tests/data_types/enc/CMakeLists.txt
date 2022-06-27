# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../data_types.edl)

# Invoke oeedger8r to generate edge routines (*_t.c, *_t.h, and *_args.h)
add_custom_command(
  OUTPUT data_types_t.h data_types_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  data_types_enc
  UUID
  338a3b09-60dd-4808-8e51-afe019a11f99
  SOURCES
  enc.c
  ${CMAKE_CURRENT_BINARY_DIR}/data_types_t.c)

# Add include paths
enclave_include_directories(data_types_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
