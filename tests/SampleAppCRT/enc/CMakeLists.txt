# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../SampleAppCRT.edl)

add_custom_command(
  OUTPUT SampleAppCRT_t.h SampleAppCRT_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  SampleAppCRT
  UUID
  31c4ecec-b94a-432a-ab76-4df401b6ee59
  SOURCES
  SampleAppCRT.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/SampleAppCRT_t.c)

enclave_include_directories(SampleAppCRT PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                            ${CMAKE_CURRENT_SOURCE_DIR})

enclave_link_libraries(SampleAppCRT oelibc)
