# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../eeid_plugin.edl)

add_custom_command(
  OUTPUT eeid_plugin_t.h eeid_plugin_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  eeid_plugin_enc
  UUID
  0ed4cfa8-3d98-4ef6-a8e6-b3120517ccad
  CONFIG
  enc.conf
  SOURCES
  enc.c
  ../test_helpers.c
  ${CMAKE_CURRENT_BINARY_DIR}/eeid_plugin_t.c)

enclave_compile_definitions(eeid_plugin_enc PRIVATE OE_WITH_EXPERIMENTAL_EEID)
enclave_include_directories(eeid_plugin_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(eeid_plugin_enc oeenclave oelibc)
