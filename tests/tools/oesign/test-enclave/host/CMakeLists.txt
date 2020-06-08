# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../helloworld.edl)

add_custom_command(
  OUTPUT helloworld_u.h helloworld_u.c helloworld_args.h
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(oesign_test_host host.c
                                ${CMAKE_CURRENT_BINARY_DIR}/helloworld_u.c)

target_include_directories(
  oesign_test_host PRIVATE # Needed for the generated file helloworld_u.h
                           ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(oesign_test_host oehost)
