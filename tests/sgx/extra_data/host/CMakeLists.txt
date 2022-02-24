# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../extra_data.edl)

add_custom_command(
  OUTPUT extra_data_u.h extra_data_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(extra_data_host host.c extra_data_u.c)

target_include_directories(extra_data_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

if (UNIX)
  # TODO issue #4130: Need to find a way around hard-coding host application base address
  # on the application CMakeLists.txt.
  target_link_libraries(extra_data_host oehost -Wl,-Ttext-segment,0x10000000)
else ()
  target_link_libraries(extra_data_host oehost)
endif ()
