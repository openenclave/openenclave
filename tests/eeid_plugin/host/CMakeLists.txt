# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set (EDL_FILE ../eeid_plugin.edl)

add_custom_command(
    OUTPUT eeid_plugin_u.h eeid_plugin_u.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r --untrusted ${EDL_FILE} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(eeid_plugin_host host.c
    ../plugin/eeid_plugin.c
    ../plugin/eeid_attester.c
    ../plugin/eeid_verifier.c
    ../plugin/test_helpers.c
    eeid_plugin_u.c)

target_include_directories(eeid_plugin_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(eeid_plugin_host oehostapp)