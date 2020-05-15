# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../exclude_system_edl.edl)

# Note: This pathing hack is to work around the fact that EDL/oeedger8r does
# not support C preprocessor macros as suggested in #2833. If that is
# implemented this will no longer be needed.
if (OE_SGX)
  add_custom_command(
    OUTPUT exclude_system_edl_u.h exclude_system_edl_u.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND
      edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/edl
      --search-path ${PROJECT_SOURCE_DIR}/edl/sgx --search-path
      ${CMAKE_CURRENT_SOURCE_DIR})
elseif (OE_TRUSTZONE)
  add_custom_command(
    OUTPUT exclude_system_edl_u.h exclude_system_edl_u.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND
      edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/edl
      --search-path ${PROJECT_SOURCE_DIR}/edl/optee --search-path
      ${CMAKE_CURRENT_SOURCE_DIR})
endif ()

add_executable(exclude_system_edl_host host.c exclude_system_edl_u.c)

target_include_directories(exclude_system_edl_host
                           PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(exclude_system_edl_host oehost)
