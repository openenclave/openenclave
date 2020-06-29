# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include(add_dcap_client_target)

set(EDL_FILE ../tests.edl)

add_custom_command(
  OUTPUT tests_u.h tests_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(report_host host.cpp tcbinfo.cpp ../common/tests.cpp tests_u.c)

if (HAS_QUOTE_PROVIDER)
  target_compile_definitions(report_host PRIVATE OE_LINK_SGX_DCAP_QL)
endif ()

add_custom_command(
  TARGET report_host
  COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/../data
          ${CMAKE_CURRENT_BINARY_DIR}/../data
  COMMAND
    ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/../data_v2
    ${CMAKE_CURRENT_BINARY_DIR}/../data_v2)

target_include_directories(
  report_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                      ${CMAKE_CURRENT_SOURCE_DIR}/../common)
target_link_libraries(report_host oehost)

# On Windows, explicitly add the nuget dependencies for the DCAP client to the target executable
if (WIN32)
  add_dcap_client_target(report_host_dcap_client)
  add_dependencies(report_host report_host_dcap_client)
endif ()
