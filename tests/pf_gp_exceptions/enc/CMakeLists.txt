# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../pf_gp_exceptions.edl)

add_custom_command(
  OUTPUT pf_gp_exceptions_t.h pf_gp_exceptions_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

string(TOUPPER "${CMAKE_BUILD_TYPE}" uppercase_CMAKE_BUILD_TYPE)
if ("${uppercase_CMAKE_BUILD_TYPE}" STREQUAL "DEBUG")
  set(CONF_TYPE "debug")
else ()
  set(CONF_TYPE "release")
endif ()

add_enclave(
  TARGET
  sgx_pf_gp_exceptions_enc
  CONFIG
  sign_${CONF_TYPE}.conf
  SOURCES
  enc.c
  ${CMAKE_CURRENT_BINARY_DIR}/pf_gp_exceptions_t.c)

add_enclave(TARGET sgx_pf_gp_exceptions_enc_unsigned SOURCES enc.c
            ${CMAKE_CURRENT_BINARY_DIR}/pf_gp_exceptions_t.c)

if ("${CMAKE_BUILD_TYPE}" STREQUAL "DEBUG")
  enclave_compile_definitions(sgx_pf_gp_exceptions_enc PRIVATE DEBUG_BUILD)
endif ()

enclave_include_directories(sgx_pf_gp_exceptions_enc PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})

enclave_include_directories(sgx_pf_gp_exceptions_enc_unsigned PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})
