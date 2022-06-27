# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../module_loading.edl)

add_custom_command(
  OUTPUT module_loading_u.h module_loading_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(module_loading_host host.c module_loading_u.c)

target_include_directories(module_loading_host
                           PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(module_loading_host oehost)
