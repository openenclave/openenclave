# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../test.edl)

add_custom_command(
  OUTPUT test_t.h test_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_custom_target(
  gmp
  COMMAND apkman add gmp-dev
  DEPENDS apkman-init)

add_enclave(
  TARGET
  gmp_enc
  UUID
  71b0822f-42a3-4543-a97c-ca491f76b82c
  SOURCES
  enc.c
  chudnovsky.c
  stubs.c
  ${CMAKE_CURRENT_BINARY_DIR}/test_t.c)

add_dependencies(gmp_enc gmp)

enclave_include_directories(
  gmp_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
  # gmp include path.
  ${APKMAN_ROOT}/usr/include)

enclave_compile_options(
  gmp_enc
  PRIVATE
  -Wno-sign-conversion
  -Wno-implicit-float-conversion
  -Wno-int-conversion
  -Wno-float-conversion
  -Wno-shorten-64-to-32)

enclave_link_libraries(
  gmp_enc
  # To use package built from source uncomment this line.
  # -L${APKMAN_ROOT}/apkbuild/pkgs/usr/lib
  -L${APKMAN_ROOT}/usr/lib
  libgmp.a
  oelibc
  # Allow undefine symbols for unused parts of gmp.
  -Wl,--warn-unresolved-symbols)
