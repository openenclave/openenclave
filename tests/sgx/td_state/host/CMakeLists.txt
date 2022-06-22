# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../td_state.edl)

add_custom_command(
  OUTPUT td_state_u.h td_state_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(td_state_host host.c td_state_u.c)

target_include_directories(td_state_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(td_state_host oehost)
