# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../enclaveparam.edl)

add_custom_command(
  OUTPUT enclaveparam_u.h enclaveparam_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(enclaveparam_host host.c enclaveparam_u.c)

target_include_directories(enclaveparam_host
                           PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(enclaveparam_host oehost)
