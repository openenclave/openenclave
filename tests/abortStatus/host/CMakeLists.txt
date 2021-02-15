# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../abortStatus.edl)

add_custom_command(
  OUTPUT abortStatus_u.h abortStatus_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(abortStatus_host host.cpp abortStatus_u.c)

if (USE_DEBUG_MALLOC)
  target_compile_definitions(abortStatus_host PRIVATE OE_USE_DEBUG_MALLOC)
endif ()

target_include_directories(abortStatus_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
                                                    ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(abortStatus_host oehost)
