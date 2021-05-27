# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../sgxextra.edl)

add_custom_command(
  OUTPUT sgxextra_u.h sgxextra_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(sgxextra_host host.c sgxextra_u.c)

target_include_directories(sgxextra_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(sgxextra_host oehost)
