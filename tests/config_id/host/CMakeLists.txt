# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../config_id.edl)

add_custom_command(
  OUTPUT config_id_u.h config_id_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(config_id_host host.cpp config_id_u.c)

target_include_directories(config_id_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                                                  ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(config_id_host oehost)
