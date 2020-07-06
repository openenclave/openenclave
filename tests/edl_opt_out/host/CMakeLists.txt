# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../edl/edl_opt_out.edl)

add_custom_command(
  OUTPUT edl_opt_out_u.h edl_opt_out_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

set(PLATFORM_EDL_FILE ../edl/header.edl)
add_custom_command(
  OUTPUT header_u.h
  DEPENDS ${PLATFORM_EDL_FILE} edger8r
  COMMAND
    edger8r --header-only --untrusted ${PLATFORM_EDL_FILE} --search-path
    ${PROJECT_SOURCE_DIR}/include ${DEFINE_OE_SGX} --search-path
    ${CMAKE_CURRENT_SOURCE_DIR})
add_custom_target(untrusted_header DEPENDS header_u.h)

add_executable(edl_opt_out_host host.c edl_opt_out_u.c)

add_dependencies(edl_opt_out_host untrusted_header)

target_include_directories(edl_opt_out_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(edl_opt_out_host oehost)
