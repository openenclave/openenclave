# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include(../cmake/add-enclave.cmake)

add_custom_command(
  OUTPUT
    [[project-name]]_t.h
    [[project-name]]_t.c
    [[project-name]]_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/[[project-name]].edl
  COMMAND
    openenclave::oeedger8r
      --trusted ${CMAKE_SOURCE_DIR}/[[project-name]].edl
      --search-path ${OE_INCLUDEDIR}
      --search-path ${OE_INCLUDEDIR}/openenclave/edl/${OE_EDL_REL_PATH})

add_enclave(
  TARGET [[project-name]]_enclave
  UUID [[generated-uuid]]
    SOURCES
    enc.c
    ${CMAKE_CURRENT_BINARY_DIR}/[[project-name]]_t.c)
