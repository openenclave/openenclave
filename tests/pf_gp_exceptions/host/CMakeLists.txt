# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../pf_gp_exceptions.edl)

add_custom_command(
  OUTPUT pf_gp_exceptions_u.h pf_gp_exceptions_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(pf_gp_exceptions_host host.c pf_gp_exceptions_u.c)

string(TOUPPER ${CMAKE_BUILD_TYPE} BUILD_TYPE_UPPER)
if (BUILD_TYPE_UPPER STREQUAL "DEBUG")
  target_compile_definitions(pf_gp_exceptions_host PRIVATE DEBUG)
endif ()

target_include_directories(pf_gp_exceptions_host
                           PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(pf_gp_exceptions_host oehost)
