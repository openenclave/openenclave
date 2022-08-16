# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../dcap_quoteprov_log.edl)

add_custom_command(
  OUTPUT dcap_quoteprov_log_u.h dcap_quoteprov_log_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(dcap_quoteprov_log_host host.c dcap_quoteprov_log_u.c)

target_include_directories(dcap_quoteprov_log_host
                           PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(dcap_quoteprov_log_host oehost)
