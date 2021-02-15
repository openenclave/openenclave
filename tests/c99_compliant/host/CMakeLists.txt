# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../c99_compliant.edl)

add_custom_command(
  OUTPUT c99_compliant_u.h c99_compliant_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(c99_compliant_host host.c c99_compliant_u.c)

target_include_directories(c99_compliant_host
                           PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(c99_compliant_host oehost)
