# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_custom_command(
  OUTPUT ssp_u.h ssp_u.c ssp_args.h
  DEPENDS ../ssp.edl edger8r
  COMMAND
    edger8r --untrusted ${CMAKE_CURRENT_SOURCE_DIR}/../ssp.edl --search-path
    ${PROJECT_SOURCE_DIR}/include --search-path ${PLATFORM_EDL_DIR})

add_executable(ssp_host host.cpp ${CMAKE_CURRENT_BINARY_DIR}/ssp_u.c)

target_include_directories(ssp_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(ssp_host oehost)
