# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../switchless_worksleep.edl)

add_custom_command(
  OUTPUT switchless_worksleep_u.h switchless_worksleep_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(switchless_worksleep_host host.cpp switchless_worksleep_u.c)

target_include_directories(switchless_worksleep_host
                           PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(switchless_worksleep_host oehost)
