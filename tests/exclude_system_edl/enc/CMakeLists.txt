# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../exclude_system_edl.edl)

# Note: This pathing hack is to work around the fact that EDL/oeedger8r does
# not support C preprocessor macros as suggested in #2833. If that is
# implemented this will no longer be needed.
if (OE_SGX)
  add_custom_command(
    OUTPUT exclude_system_edl_t.h exclude_system_edl_t.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND
      edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/edl
      --search-path ${PROJECT_SOURCE_DIR}/edl/sgx --search-path
      ${CMAKE_CURRENT_SOURCE_DIR})
elseif (OE_TRUSTZONE)
  add_custom_command(
    OUTPUT exclude_system_edl_t.h exclude_system_edl_t.c
    DEPENDS ${EDL_FILE} edger8r
    COMMAND
      edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/edl
      --search-path ${PROJECT_SOURCE_DIR}/edl/optee --search-path
      ${CMAKE_CURRENT_SOURCE_DIR})
endif ()

add_enclave(
  TARGET
  exclude_system_edl_enc
  UUID
  610cd59d-49cd-4344-b1a3-7eb90df999dc
  SOURCES
  enc.c
  ${CMAKE_CURRENT_BINARY_DIR}/exclude_system_edl_t.c)

enclave_include_directories(exclude_system_edl_enc PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(exclude_system_edl_enc oelibc)
