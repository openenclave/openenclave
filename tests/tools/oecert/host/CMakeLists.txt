# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_custom_command(
  OUTPUT oecert_u.h oecert_u.c oecert_args.h
  DEPENDS ../oecert.edl edger8r
  COMMAND edger8r --untrusted ${CMAKE_CURRENT_SOURCE_DIR}/../oecert.edl)

add_executable(oecert host.cpp ${CMAKE_CURRENT_BINARY_DIR}/oecert_u.c)

target_include_directories(oecert PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(oecert oehost)
