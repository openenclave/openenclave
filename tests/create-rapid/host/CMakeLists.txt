# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../create_rapid.edl)

add_custom_command(
  OUTPUT create_rapid_u.h create_rapid_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(create_rapid_host host.cpp create_rapid_u.c)

target_include_directories(create_rapid_host
                           PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(create_rapid_host oehost)
