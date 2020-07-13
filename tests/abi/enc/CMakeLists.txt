# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../abi.edl)

add_custom_command(
  OUTPUT abi_t.h abi_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  abi_enc
  UUID
  7B7FB79E-2B73-46C5-8C30-3A71C014BD85
  SOURCES
  enc.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/abi_t.c)

enclave_include_directories(abi_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                            ${CMAKE_CURRENT_SOURCE_DIR})
enclave_link_libraries(abi_enc oelibc)
