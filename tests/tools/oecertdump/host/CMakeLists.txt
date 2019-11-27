# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_custom_command(OUTPUT oecertdump_u.h oecertdump_u.c oecertdump_args.h
  DEPENDS ../oecertdump.edl edger8r
  COMMAND edger8r --untrusted ${CMAKE_CURRENT_SOURCE_DIR}/../oecertdump.edl)

add_executable(oecertdump host.cpp ${CMAKE_CURRENT_BINARY_DIR}/oecertdump_u.c)

target_include_directories(oecertdump PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(oecertdump oehost)