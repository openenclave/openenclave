# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../set_log_level_a.edl)
set(EDL_FILE_WITHOUT_ENC_LOGGING ../set_log_level_b.edl)

add_custom_command(
  OUTPUT set_log_level_a_u.h set_log_level_a_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_custom_command(
  OUTPUT set_log_level_b_u.h set_log_level_b_u.c
  DEPENDS ${EDL_FILE_WITHOUT_ENC_LOGGING} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE_WITHOUT_ENC_LOGGING} --search-path
    ${PROJECT_SOURCE_DIR}/include ${DEFINE_OE_SGX} --search-path
    ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(set_log_level_host host.c set_log_level_a_u.c
                                  set_log_level_b_u.c)

target_include_directories(set_log_level_host
                           PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(set_log_level_host oehost)
