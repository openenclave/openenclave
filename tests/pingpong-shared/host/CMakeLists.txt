# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../pingpong.edl)

add_custom_command(
  OUTPUT pingpong_u.h pingpong_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_library(pingpong-shared-lib SHARED host.cpp pingpong_u.c)

target_include_directories(pingpong-shared-lib
                           PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(pingpong-shared-lib oehost)

add_executable(pingpong-shared_host main.cpp)
target_link_libraries(pingpong-shared_host pingpong-shared-lib)
