# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../split.edl)

add_custom_command(
  OUTPUT split_u.h split_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(split_host host.c split_u.c)

if (WITH_EEID)
  target_compile_definitions(split_host PRIVATE OE_WITH_EXPERIMENTAL_EEID)
endif ()

target_include_directories(split_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(split_host oehost)
