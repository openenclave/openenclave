# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include(../cmake/add-enclave.cmake)

add_custom_command(
  OUTPUT
    [[project-name]]_t.h
    [[project-name]]_t.c
    [[project-name]]_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/[[project-name]].edl
  COMMAND openenclave::oeedger8r --trusted ${CMAKE_SOURCE_DIR}/[[project-name]].edl)

add_enclave(
  TARGET [[project-name]]_enclave
  UUID [[generated-uuid]]
    SOURCES
    enc.c
    ${CMAKE_CURRENT_BINARY_DIR}/[[project-name]]_t.c)
