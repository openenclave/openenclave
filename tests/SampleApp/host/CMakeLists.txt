# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../SampleApp.edl)

add_custom_command(
  OUTPUT SampleApp_u.h SampleApp_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(SampleAppHost SampleAppHost.cpp SampleApp_u.c)

target_include_directories(SampleAppHost PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                                                 ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(SampleAppHost oehost)
