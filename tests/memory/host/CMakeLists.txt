# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../memory.edl)

add_custom_command(
  OUTPUT memory_u.h memory_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND edger8r --untrusted ${EDL_FILE} --search-path
          ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(memory_host host.cpp memory_u.c)

if (USE_DEBUG_MALLOC)
  target_compile_definitions(memory_host PRIVATE OE_USE_DEBUG_MALLOC)
endif ()

target_include_directories(memory_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(memory_host oehost)
