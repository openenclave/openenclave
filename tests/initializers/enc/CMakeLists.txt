# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../initializers.edl)

add_custom_command(
  OUTPUT initializers_t.h initializers_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND edger8r --trusted ${EDL_FILE} --search-path
          ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  initializers_enc
  UUID
  62f73b00-bdfe-4763-a06a-dc561a3a34d8
  SOURCES
  enc.c
  initializers_t.c)

enclave_include_directories(initializers_enc PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(initializers_enc oelibc)
