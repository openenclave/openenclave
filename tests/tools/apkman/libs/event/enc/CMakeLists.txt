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
  event
  COMMAND apkman add libevent-dev libevent-static
  DEPENDS apkman-init)

add_enclave(
  TARGET
  event_enc
  UUID
  71b0822f-42a3-4543-a97c-ca491f76b82c
  SOURCES
  enc.c
  echoserver.c
  # STEP 5: Implement missing functions.
  stubs.c
  ${CMAKE_CURRENT_BINARY_DIR}/test_t.c)

add_dependencies(event_enc event)

enclave_include_directories(
  event_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_BINARY_DIR}
  # libevent include path.
  ${APKMAN_ROOT}/usr/include)

enclave_compile_options(
  event_enc
  PRIVATE
  -Wno-implicit-int-conversion
  -Wno-bitwise-op-parentheses
  -Wno-shift-op-parentheses
  -Wno-shorten-64-to-32
  -Wno-implicit-float-conversion
  -Wno-sign-conversion
  -Wno-unused-parameter
  -Wno-unused-variable)

enclave_link_libraries(
  event_enc
  # To use package built from source uncomment this line.
  # -L${APKMAN_ROOT}/apkbuild/pkgs/usr/lib
  -L${APKMAN_ROOT}/usr/lib
  libevent_core.a
  oelibc
  oehostepoll
  oehostfs
  oehostsock
  # Allow undefine symbols for unused parts of sqlite.
  -Wl,--warn-unresolved-symbols)
