# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../stdc.edl)

add_custom_command(
  OUTPUT stdc_u.h stdc_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND edger8r --untrusted ${EDL_FILE} --search-path
          ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(stdc_host host.cpp stdc_u.c)

target_include_directories(stdc_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                                             ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(stdc_host oehost)
