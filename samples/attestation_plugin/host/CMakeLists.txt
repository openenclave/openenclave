# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_custom_command(OUTPUT helloworld_u.h helloworld_u.c helloworld_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/attestation_plugin.edl
  COMMAND openenclave::oeedger8r --untrusted ${CMAKE_SOURCE_DIR}/attestation_plugin.edl)

add_executable(helloworld_host host.c ${CMAKE_CURRENT_BINARY_DIR}/helloworld_u.c)

target_include_directories(helloworld_host PRIVATE
  # Needed for the generated file helloworld_u.h
  ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(helloworld_host openenclave::oehostapp)
