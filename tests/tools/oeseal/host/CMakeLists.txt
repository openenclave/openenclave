# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_custom_command(
  OUTPUT oeseal_u.h oeseal_u.c oeseal_args.h
  DEPENDS ../oeseal.edl edger8r
  COMMAND edger8r --untrusted ${CMAKE_CURRENT_SOURCE_DIR}/../oeseal.edl
          --search-path ${PROJECT_SOURCE_DIR}/include -DOE_SGX)

list(APPEND SOURCES host.c ${CMAKE_CURRENT_BINARY_DIR}/oeseal_u.c)

if (WIN32)
  list(APPEND SOURCES getopt_long.c)
endif ()

add_executable(oeseal ${SOURCES})

target_include_directories(oeseal PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

if (WIN32)
  target_include_directories(oeseal PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
endif ()

target_link_libraries(oeseal oehost)
