# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../safecrt.edl)

add_custom_command(
  OUTPUT safecrt_u.h safecrt_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(safecrt_host ../common/test.cpp host.cpp safecrt_u.c)

target_include_directories(safecrt_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(safecrt_host oehost)
