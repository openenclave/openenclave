# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../wrfsbase.edl)

add_custom_command(
  OUTPUT wrfsbase_t.h wrfsbase_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(TARGET sgx_wrfsbase_enc SOURCES enc.c
            ${CMAKE_CURRENT_BINARY_DIR}/wrfsbase_t.c)

enclave_include_directories(sgx_wrfsbase_enc PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})
