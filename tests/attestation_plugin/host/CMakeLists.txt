# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include(add_dcap_client_target)

set(EDL_FILE ../plugin.edl)

add_custom_command(
  OUTPUT plugin_u.h plugin_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(plugin_host host.c ../plugin/tests.c plugin_u.c)

target_include_directories(plugin_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(plugin_host oehost)

add_executable(plugin_lifetime_host lifetime.cpp plugin_u.c)
target_include_directories(plugin_lifetime_host
                           PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(plugin_lifetime_host oehost)
add_test(NAME tests/attestation_plugin_lifetime_host
         COMMAND plugin_lifetime_host --host-only)
set_tests_properties(tests/attestation_plugin_lifetime_host PROPERTIES TIMEOUT
                                                                       120)

# On Windows, explicitly add the nuget dependencies for the DCAP client to the target executable
if (WIN32)
  add_dcap_client_target(plugin_host_dcap_client)
  add_dependencies(plugin_host plugin_host_dcap_client)
  add_dependencies(plugin_lifetime_host plugin_host_dcap_client)
endif ()
