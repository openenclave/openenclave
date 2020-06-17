# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../eeid_plugin.edl)

add_custom_command(
  OUTPUT eeid_plugin_u.h eeid_plugin_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(eeid_plugin_host host.c ../test_helpers.c eeid_plugin_u.c)

target_compile_definitions(eeid_plugin_host PRIVATE OE_WITH_EXPERIMENTAL_EEID)
target_include_directories(eeid_plugin_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(eeid_plugin_host oehost oehostverify oehost)
