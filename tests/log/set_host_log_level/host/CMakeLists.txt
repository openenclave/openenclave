# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../set_host_log_level.edl)

add_custom_command(
  OUTPUT set_host_log_level_u.h set_host_log_level_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(set_host_log_level_host host.c set_host_log_level_u.c)

target_include_directories(set_host_log_level_host
                           PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(set_host_log_level_host oehost)
