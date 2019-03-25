# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_custom_command(OUTPUT datasealing_u.h datasealing_u.c
  DEPENDS ${CMAKE_SOURCE_DIR}/datasealing.edl
  COMMAND openenclave::oeedger8r --untrusted ${CMAKE_SOURCE_DIR}/datasealing.edl)

add_executable(data-sealing_host host.cpp ${CMAKE_CURRENT_BINARY_DIR}/datasealing_u.c)

target_include_directories(data-sealing_host PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../ # For common/shared.h
  ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(data-sealing_host openenclave::oehostapp)
