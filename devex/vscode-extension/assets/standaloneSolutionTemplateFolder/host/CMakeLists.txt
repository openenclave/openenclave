# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_custom_command(
  OUTPUT
    [[project-name]]_u.h
    [[project-name]]_u.c
    [[project-name]]_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/[[project-name]].edl
  COMMAND
    openenclave::oeedger8r
      --untrusted ${CMAKE_SOURCE_DIR}/[[project-name]].edl
      --search-path ${OE_INCLUDEDIR}
      --search-path ${OE_INCLUDEDIR}/openenclave/edl/${OE_EDL_REL_PATH})

add_executable([[project-name]]
    host.c
    main.c
    ${CMAKE_CURRENT_BINARY_DIR}/[[project-name]]_u.c)

if (WIN32)
  copy_oedebugrt_target(helloworld_host_oedebugrt)
  add_dependencies(helloworld_host helloworld_host_oedebugrt)
endif ()

# Needed for the generated *_u.h header.
target_include_directories([[project-name]] PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries([[project-name]] openenclave::oehost)
