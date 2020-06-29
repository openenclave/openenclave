# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../file.edl)

add_custom_command(
  OUTPUT file_t.h file_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  file_enc
  UUID
  f7ee9123-07ec-4d46-81ac-47a109b1d406
  SOURCES
  enc.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/file_t.c)
enclave_include_directories(file_enc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
                            ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(file_enc oelibc)
