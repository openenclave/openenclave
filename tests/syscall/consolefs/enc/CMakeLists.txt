# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../consolefs.edl)

add_custom_command(
  OUTPUT consolefs_t.h consolefs_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(TARGET consolefs_enc SOURCES enc.c
            ${CMAKE_CURRENT_BINARY_DIR}/consolefs_t.c)
enclave_include_directories(consolefs_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
maybe_build_using_clangw(consolefs_enc)
enclave_link_libraries(consolefs_enc oelibc oeenclave)
