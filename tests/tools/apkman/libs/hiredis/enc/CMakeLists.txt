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
  hiredis
  COMMAND apkman add hiredis-dev
  DEPENDS apkman-init)

add_enclave(
  TARGET
  hiredis_enc
  UUID
  71b0822f-42a3-4543-a97c-ca491f76b82c
  SOURCES
  enc.c
  example.c
  stubs.c
  ${CMAKE_CURRENT_BINARY_DIR}/test_t.c)

add_dependencies(hiredis_enc hiredis)

enclave_include_directories(
  hiredis_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
  # Path for hiredis headers
  ${APKMAN_ROOT}/usr/include/hiredis ${APKMAN_ROOT}/usr/include)

enclave_compile_options(
  hiredis_enc
  PRIVATE
  -Wno-sign-conversion
  -Wno-shorten-64-to-32
  -Wno-shift-op-parentheses
  -Wno-implicit-int-conversion
  -Wno-bitwise-op-parentheses)

enclave_link_libraries(
  hiredis_enc
  # Uncomment below to use custom build package.
  # -L${APKMAN_ROOT}/apkbuild/pkgs/usr/lib
  -L${APKMAN_ROOT}/usr/lib
  libhiredis.a
  oelibc
  oehostepoll
  oehostfs
  oehostsock
  oehostresolver
  -fuse-ld=${CMAKE_CURRENT_SOURCE_DIR}/../../../utils/ld
  # Allow missing symbols for development.
  -Wl,--warn-unresolved-symbols)
