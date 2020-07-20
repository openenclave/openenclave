# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../tls_e2e.edl)

add_custom_command(
  OUTPUT tls_e2e_t.h tls_e2e_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  tls_client_enc
  SOURCES
  client.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/tls_e2e_t.c
  ../common/utility.cpp
  tls_e2e_t.c)

set_source_files_properties(tls_e2e_t.c PROPERTIES COMPILE_FLAGS
                                                   "-Wno-conversion")

enclave_include_directories(tls_client_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                            ${CMAKE_CURRENT_SOURCE_DIR})

enclave_link_libraries(tls_client_enc oeenclave oelibc oehostsock
                       oehostresolver)
