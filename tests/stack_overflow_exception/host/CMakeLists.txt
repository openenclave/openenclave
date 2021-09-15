# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../stack_overflow_exception.edl)

add_custom_command(
  OUTPUT stack_overflow_exception_u.h stack_overflow_exception_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(stack_overflow_exception_host host.c
                                             stack_overflow_exception_u.c)

string(TOUPPER ${CMAKE_BUILD_TYPE} BUILD_TYPE_UPPER)
if (BUILD_TYPE_UPPER STREQUAL "DEBUG")
  target_compile_definitions(stack_overflow_exception_host PRIVATE DEBUG_BUILD)
endif ()

target_include_directories(stack_overflow_exception_host
                           PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(stack_overflow_exception_host oehost)
