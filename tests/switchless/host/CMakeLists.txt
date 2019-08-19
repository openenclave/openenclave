# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_custom_command(
  OUTPUT switchless_u.h switchless_u.c switchless_args.h
  DEPENDS ../switchless.edl
  COMMAND edger8r --experimental --untrusted --search-path ${CMAKE_CURRENT_SOURCE_DIR}/.. switchless.edl)

# Dummy target used for generating from EDL on demand.
add_custom_target(switchless_host_gen DEPENDS switchless_u.h switchless_u.c switchless_args.h)

add_executable(switchless_host host.c switchless_u.c)

target_include_directories(switchless_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(switchless_host oehostapp)
