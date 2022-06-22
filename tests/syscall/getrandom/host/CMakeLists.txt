# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../getrandom.edl)

add_custom_command(
  OUTPUT getrandom_u.h getrandom_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(getrandom_host host.c getrandom_u.c)

target_include_directories(getrandom_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(getrandom_host oehost)
