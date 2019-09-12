# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_custom_command(OUTPUT matrix_u.h matrix_u.c matrix_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/matrix.edl
  COMMAND openenclave::oeedger8r --untrusted ${CMAKE_SOURCE_DIR}/matrix.edl)

add_executable(matrix_host
    host.c
    ${CMAKE_CURRENT_BINARY_DIR}/matrix_u.c
    ${CMAKE_SOURCE_DIR}/common/multiply.c
    ${CMAKE_SOURCE_DIR}/common/multiply.h)

target_include_directories(matrix_host PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(matrix_host openenclave::oehostapp)
