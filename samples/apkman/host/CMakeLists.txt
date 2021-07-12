# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_custom_command(
  OUTPUT sqlite_u.h sqlite_u.c sqlite_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/sqlite.edl
  COMMAND
    openenclave::oeedger8r --untrusted ${CMAKE_SOURCE_DIR}/sqlite.edl
    --search-path ${OE_INCLUDEDIR} --search-path
    ${OE_INCLUDEDIR}/openenclave/edl/sgx)

add_executable(sqlite_host host.c ${CMAKE_CURRENT_BINARY_DIR}/sqlite_u.c)

target_include_directories(sqlite_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(sqlite_host openenclave::oehost)
