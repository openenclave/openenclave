# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Build enclave shared object dependencies
set(LDD_TEST_ENC_DIR ${CMAKE_CURRENT_BINARY_DIR})
add_subdirectory(dep_1a)
add_subdirectory(dep_1b)

# Build test enclave
set(EDL_FILE ../ldd.edl)

add_custom_command(
  OUTPUT ldd_t.h ldd_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  ldd_enc
  UUID
  F3E7FC46-7173-413C-8FA3-EB8336391BC1
  SOURCES
  enc.c
  ${CMAKE_CURRENT_BINARY_DIR}/ldd_t.c)

enclave_include_directories(ldd_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
enclave_link_libraries(ldd_enc oelibc ldd_enc_dep_1a ldd_enc_dep_1b)
