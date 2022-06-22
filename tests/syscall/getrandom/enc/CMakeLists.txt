# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../getrandom.edl)

add_custom_command(
  OUTPUT getrandom_t.h getrandom_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(TARGET getrandom_enc SOURCES enc.c
            ${CMAKE_CURRENT_BINARY_DIR}/getrandom_t.c)
enclave_include_directories(getrandom_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
maybe_build_using_clangw(getrandom_enc)
enclave_link_libraries(getrandom_enc oelibc oeenclave)
