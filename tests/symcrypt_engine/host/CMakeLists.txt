# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../symcrypt_engine.edl)

add_custom_command(
  OUTPUT symcrypt_engine_u.h symcrypt_engine_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(symcrypt_engine_host host.c symcrypt_engine_u.c)

target_include_directories(symcrypt_engine_host
                           PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(symcrypt_engine_host oehost)
