# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_custom_command(
  OUTPUT switchless_t.h switchless_t.c switchless_args.h
  DEPENDS ../switchless.edl
  COMMAND edger8r --experimental --trusted --search-path ${CMAKE_CURRENT_SOURCE_DIR}/.. switchless.edl)

# Dummy target used for generating from EDL on demand.
add_custom_target(switchless_enc_gen DEPENDS switchless_t.h switchless_t.c switchless_args.h)

add_enclave(TARGET switchless_enc UUID d497e154-9e8e-4029-a53d-c0a36533fb95 SOURCES enc.c switchless_t.c)

target_include_directories(switchless_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(switchless_enc oelibc)
