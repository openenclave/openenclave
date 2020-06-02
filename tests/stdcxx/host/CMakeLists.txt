# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../stdcxx.edl)

add_custom_command(
  OUTPUT stdcxx_u.h stdcxx_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(stdcxx_host host.cpp stdcxx_u.c)

target_include_directories(stdcxx_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                                               ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(stdcxx_host oehost)
