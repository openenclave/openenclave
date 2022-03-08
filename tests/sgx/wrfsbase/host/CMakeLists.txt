# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../wrfsbase.edl)

add_custom_command(
  OUTPUT wrfsbase_u.h wrfsbase_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(wrfsbase_host host.c wrfsbase_u.c)

target_include_directories(wrfsbase_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(wrfsbase_host oehost)
