# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../sim_mode.edl)

add_custom_command(
  OUTPUT sim_mode_u.h sim_mode_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(sim_host host.c sim_mode_u.c)

target_include_directories(sim_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(sim_host oehost)
