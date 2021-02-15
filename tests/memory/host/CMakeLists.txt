# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Use full path to edl file to avoid ${PLATFORM_EDL_DIR}/../memory.edl
# from getting picked up instead.
set(EDL_FILE ${CMAKE_CURRENT_SOURCE_DIR}/../memory.edl)

add_custom_command(
  OUTPUT memory_u.h memory_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND edger8r --untrusted ${EDL_FILE} --search-path
          ${PROJECT_SOURCE_DIR}/include ${DEFINE_OE_SGX})

add_executable(memory_host host.cpp memory_u.c)

if (USE_DEBUG_MALLOC)
  target_compile_definitions(memory_host PRIVATE OE_USE_DEBUG_MALLOC)
endif ()

target_include_directories(memory_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(memory_host oehost)
