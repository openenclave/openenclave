# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../no_tdata.edl)

add_custom_command(
  OUTPUT no_tdata_u.h no_tdata_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(no_tdata_host host.cpp no_tdata_u.c)

target_include_directories(no_tdata_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_compile_options(no_tdata_host
                       PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-std=c++11>)
target_link_libraries(no_tdata_host oehost)
