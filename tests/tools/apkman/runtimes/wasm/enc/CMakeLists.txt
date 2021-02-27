# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# WASM runtime: https://github.com/wasm3/wasm3

set(EDL_FILE ../test.edl)

add_custom_command(
  OUTPUT test_t.h test_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

add_custom_command(
  OUTPUT main.o libuvwasi_a.a libuv_a.a libm3.a
  COMMAND apkman add build-base cmake
  COMMAND rm -rf wasm3
  COMMAND apkman exec sh ${CMAKE_CURRENT_SOURCE_DIR}/build-wasm.sh
  DEPENDS apkman-init)

add_enclave(
  TARGET
  wasm_enc
  UUID
  71b0822f-42a3-4543-a97c-ca491f76b82c
  SOURCES
  enc.c
  stubs.c
  main.o
  ${CMAKE_CURRENT_BINARY_DIR}/test_t.c)

enclave_include_directories(
  wasm_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
  # wasm include path.
  ${APKMAN_ROOT}/usr/include)

enclave_compile_options(
  wasm_enc
  PRIVATE
  -Wno-sign-conversion
  -Wno-visibility
  -Wno-implicit-int-conversion
  -Wno-bitwise-op-parentheses
  -Wno-shift-op-parentheses
  -Wno-shorten-64-to-32)

# Ideally, wasm needs pthread_create.
# None of the test benchmarks need it though.
enclave_link_libraries(
  wasm_enc
  -L${CMAKE_CURRENT_BINARY_DIR}
  libm3.a
  libuvwasi_a.a
  libuv_a.a
  oelibc
  oehostfs
  -fuse-ld=${CMAKE_CURRENT_SOURCE_DIR}/../../../utils/ld
  -Wl,--warn-unresolved-symbols)
