# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../echo.edl)

add_custom_command(
  OUTPUT echo_u.h echo_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(echo_host host.c echo_u.c)

target_include_directories(echo_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(echo_host oehost)
