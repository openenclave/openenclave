# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../sealKey.edl)

add_custom_command(
  OUTPUT sealKey_u.h sealKey_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    --search-path ${PLATFORM_EDL_DIR} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(sealKey_host host.cpp sealKey_u.c)

target_include_directories(sealKey_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                                                ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(sealKey_host oehost)
