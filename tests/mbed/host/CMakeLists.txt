# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../mbed.edl)

add_custom_command(
  OUTPUT mbed_u.h mbed_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(libmbedtest_host host.c ocalls.c mbed_u.c)

target_compile_definitions(libmbedtest_host
                           PRIVATE PROJECT_DIR="${CMAKE_CURRENT_BINARY_DIR}/")
if (NOT WIN32)
  target_compile_options(libmbedtest_host PRIVATE -Wno-error)
endif ()

target_include_directories(libmbedtest_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                                                    ..)
target_link_libraries(libmbedtest_host oehost)
