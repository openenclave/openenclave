# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_custom_command(
  OUTPUT
    [[project-name]]_u.h
    [[project-name]]_u.c
    [[project-name]]_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/[[project-name]].edl
  COMMAND openenclave::oeedger8r --untrusted ${CMAKE_SOURCE_DIR}/[[project-name]].edl)

add_executable([[project-name]]
    host.c
    main.c
    ${CMAKE_CURRENT_BINARY_DIR}/[[project-name]]_u.c)

target_include_directories([[project-name]] PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries([[project-name]] openenclave::oehost)
