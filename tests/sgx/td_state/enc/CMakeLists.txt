# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../td_state.edl)

add_custom_command(
  OUTPUT td_state_t.h td_state_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(TARGET sgx_td_state_enc SOURCES enc.c
            ${CMAKE_CURRENT_BINARY_DIR}/td_state_t.c)

enclave_include_directories(sgx_td_state_enc PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(sgx_td_state_enc oelibc)
