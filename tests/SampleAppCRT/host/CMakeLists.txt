# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../SampleAppCRT.edl)

add_custom_command(
  OUTPUT SampleAppCRT_u.h SampleAppCRT_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(SampleAppCRTHost SampleAppCRTHost.cpp SampleAppCRT_u.c)

target_include_directories(SampleAppCRTHost PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                                                    ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(SampleAppCRTHost oehost)
