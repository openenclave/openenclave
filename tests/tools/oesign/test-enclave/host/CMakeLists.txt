# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../oesign_test.edl)

add_custom_command(
  OUTPUT oesign_test_u.h oesign_test_u.c oesign_test_args.h
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(oesign_test_host host.c
                                ${CMAKE_CURRENT_BINARY_DIR}/oesign_test_u.c)

target_include_directories(
  oesign_test_host PRIVATE # Needed for the generated file oesign_test_u.h
                           ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(oesign_test_host oehost)
