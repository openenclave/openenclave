# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../file.edl)

add_custom_command(
  OUTPUT file_u.h file_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(file_host host.cpp file_u.c)

target_include_directories(file_host PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
                                             ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(file_host oehost)
