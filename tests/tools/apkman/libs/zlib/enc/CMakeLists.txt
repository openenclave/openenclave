# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../test.edl)
set(PROTO_FILE ./geometry.proto)

add_custom_command(
  OUTPUT test_t.h test_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_enclave(
  TARGET
  zlib_enc
  UUID
  71b0822f-42a3-4543-a97c-ca491f76b82c
  SOURCES
  enc.c
  zpipe.c
  ${CMAKE_CURRENT_BINARY_DIR}/test_t.c)

add_custom_target(
  zlib
  COMMAND apkman add zlib-dev zlib-static
  DEPENDS apkman-init)

add_dependencies(zlib_enc zlib)

enclave_include_directories(
  zlib_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
  # zlib include paths.
  ${APKMAN_ROOT}/usr/include)

enclave_compile_options(
  zlib_enc PRIVATE -Wno-implicit-int-conversion -Wno-bitwise-op-parentheses
  -Wno-shift-op-parentheses -Wno-shorten-64-to-32)

enclave_link_libraries(zlib_enc -L${APKMAN_ROOT}/lib libz.a oelibc
                       -Wl,--warn-unresolved-symbols)
