# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_custom_command(
  OUTPUT switchless_threads_t.h switchless_threads_t.c switchless_threads_args.h
  DEPENDS
  edger8r
  ../switchless_threads.edl
  COMMAND edger8r --experimental --trusted --search-path ${CMAKE_CURRENT_SOURCE_DIR}/.. switchless_threads.edl)

# Dummy target used for generating from EDL on demand.
add_custom_target(switchless_threads_enc_gen DEPENDS switchless_threads_t.h switchless_threads_t.c switchless_threads_args.h)

add_enclave(TARGET switchless_threads_enc UUID 6e818629-0ce7-46cd-822a-6c7e081fc68b SOURCES enc.c switchless_threads_t.c)

target_include_directories(switchless_threads_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(switchless_threads_enc oelibc)
