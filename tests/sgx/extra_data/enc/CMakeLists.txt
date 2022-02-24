# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../extra_data.edl)

add_custom_command(
  OUTPUT extra_data_t.h extra_data_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(TARGET sgx_extra_data_enc SOURCES enc.c props.c
            ${CMAKE_CURRENT_BINARY_DIR}/extra_data_t.c)

enclave_include_directories(sgx_extra_data_enc PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})

if (UNIX)
  add_enclave(TARGET sgx_extra_data_zerobase_enc SOURCES enc.c props_zerobase.c
              ${CMAKE_CURRENT_BINARY_DIR}/extra_data_t.c)

  enclave_include_directories(sgx_extra_data_zerobase_enc PRIVATE
                              ${CMAKE_CURRENT_BINARY_DIR})
endif ()
