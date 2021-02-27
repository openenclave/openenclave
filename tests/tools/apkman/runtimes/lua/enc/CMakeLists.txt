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
  lua
  COMMAND apkman add lua-dev
  DEPENDS apkman-init)

add_enclave(
  TARGET
  lua_enc
  UUID
  71b0822f-42a3-4543-a97c-ca491f76b82c
  SOURCES
  enc.c
  stubs.c
  ${CMAKE_CURRENT_BINARY_DIR}/test_t.c)

add_dependencies(lua_enc lua)

enclave_include_directories(
  lua_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
  # lua include path.
  ${APKMAN_ROOT}/usr/include)

enclave_compile_options(
  lua_enc
  PRIVATE
  -Wno-implicit-int-conversion
  -Wno-bitwise-op-parentheses
  -Wno-shift-op-parentheses
  -Wno-shorten-64-to-32
  -Wno-implicit-float-conversion)

enclave_link_libraries(lua_enc -L${APKMAN_ROOT}/usr/lib liblua.a oelibc
                       oehostfs -Wl,--warn-unresolved-symbols)
