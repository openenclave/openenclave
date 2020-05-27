# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../custom_claims.edl)

add_custom_command(
  OUTPUT custom_claims_u.h custom_claims_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(custom_claims_host host.c ../test_common/tests.c
                                  custom_claims_u.c)

target_include_directories(custom_claims_host
                           PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(custom_claims_host oehost)
