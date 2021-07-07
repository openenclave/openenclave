# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../symcrypt_engine.edl)
set(NO_ENTROPY_EDL_FILE ../symcrypt_engine_no_entropy.edl)

add_custom_command(
  OUTPUT symcrypt_engine_u.h symcrypt_engine_u.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_custom_command(
  OUTPUT symcrypt_engine_no_entropy_u.h symcrypt_engine_no_entropy_u.c
  DEPENDS ${NO_ENTROPY_EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${NO_ENTROPY_EDL_FILE} --search-path
    ${PROJECT_SOURCE_DIR}/include ${DEFINE_OE_SGX} --search-path
    ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(symcrypt_engine_host host.c symcrypt_engine_u.c)
add_executable(symcrypt_engine_no_entropy_host host.c
                                               symcrypt_engine_no_entropy_u.c)

target_compile_definitions(symcrypt_engine_host PRIVATE USE_ENTROPY_EDL)

target_include_directories(symcrypt_engine_host
                           PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories(symcrypt_engine_no_entropy_host
                           PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(symcrypt_engine_host oehost)
target_link_libraries(symcrypt_engine_no_entropy_host oehost)
