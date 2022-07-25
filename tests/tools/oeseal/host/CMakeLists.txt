# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_custom_command(
  OUTPUT oeseal_u.h oeseal_u.c oeseal_args.h
  DEPENDS ../oeseal.edl edger8r
  COMMAND edger8r --untrusted ${CMAKE_CURRENT_SOURCE_DIR}/../oeseal.edl
          --search-path ${PROJECT_SOURCE_DIR}/include -DOE_SGX)

add_executable(oeseal host.c ${CMAKE_CURRENT_BINARY_DIR}/oeseal_u.c)

target_include_directories(oeseal PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(oeseal oehost)
