# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_custom_command(
  OUTPUT switchless_threads_u.h switchless_threads_u.c switchless_threads_args.h
  DEPENDS
  edger8r
  ../switchless_threads.edl
  COMMAND edger8r --experimental --untrusted --search-path ${CMAKE_CURRENT_SOURCE_DIR}/.. switchless_threads.edl)

# Dummy target used for generating from EDL on demand.
add_custom_target(switchless_threads_host_gen DEPENDS switchless_threads_u.h switchless_threads_u.c switchless_threads_args.h)

add_executable(switchless_threads_host host.c switchless_threads_u.c)

target_include_directories(switchless_threads_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(switchless_threads_host oehostapp)
