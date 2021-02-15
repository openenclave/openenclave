# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../openssl.edl)

add_custom_command(
  OUTPUT openssl_u.h openssl_u.c openssl_args.h
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --untrusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(openssl_host host.cpp openssl_u.c)

target_include_directories(openssl_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(openssl_host oehost)
