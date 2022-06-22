# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../alignment.edl)

add_custom_command(
  OUTPUT alignment_u.h alignment_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(alignment_host host.c alignment_u.c)

target_include_directories(alignment_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(alignment_host oehost)
