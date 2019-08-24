# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_custom_command(OUTPUT oecert_t.h oecert_t.c oecert_args.h
  DEPENDS ../oecert.edl
  COMMAND edger8r --trusted ${CMAKE_CURRENT_SOURCE_DIR}/../oecert.edl)

add_executable(oecert_enc enc.cpp ${CMAKE_CURRENT_BINARY_DIR}/oecert_t.c)

# Need for the generated file oecert_t.h
target_include_directories(oecert_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(oecert_enc oeenclave oelibc)
