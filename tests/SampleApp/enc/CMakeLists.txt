# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../SampleApp.edl)

add_custom_command(
  OUTPUT SampleApp_t.h SampleApp_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  SampleApp
  UUID
  25419627-14f6-4625-9329-cf5f10a57fea
  SOURCES
  SampleApp.cpp
  ${CMAKE_CURRENT_BINARY_DIR}/SampleApp_t.c)

enclave_include_directories(SampleApp PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                            ${CMAKE_CURRENT_SOURCE_DIR})

enclave_link_libraries(SampleApp oelibc)
