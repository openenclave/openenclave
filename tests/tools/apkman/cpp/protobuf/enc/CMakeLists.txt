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
  protobuf
  COMMAND apkman add protoc protobuf-dev
  DEPENDS apkman-init)

set(PROTO_FILE types.proto)
add_custom_command(
  OUTPUT types.pb.h types.pb.cc
  COMMAND apkman add protoc protobuf-dev
  COMMAND apkman exec protoc --proto_path=${CMAKE_CURRENT_SOURCE_DIR}/..
          --cpp_out=. ${PROTO_FILE}
  DEPENDS protobuf ../${PROTO_FILE})

add_enclave(
  TARGET
  protobuf_enc
  UUID
  71b0822f-42a3-4543-a97c-ca491f76b82c
  SOURCES
  enc.cpp
  types.pb.cc
  ${CMAKE_CURRENT_BINARY_DIR}/test_t.c)

enclave_include_directories(
  protobuf_enc
  PRIVATE
  ${CMAKE_CURRENT_BINARY_DIR}
  # Protobuf headers available via protobuf-dev library.
  # C++
  ${APKMAN_ROOT}/usr/include/c++/10.2.1
  ${APKMAN_ROOT}/usr/include/c++/10.2.1/x86_64-alpine-linux-musl
  # C
  ${APKMAN_ROOT}/usr/include)

enclave_compile_options(
  protobuf_enc
  PRIVATE
  -Wno-shorten-64-to-32
  -Wno-bitwise-op-parentheses
  -Wno-shift-op-parentheses
  -Wno-sign-conversion
  -Wno-unused-parameter
  -Wno-implicit-int-conversion)

target_link_libraries(
  protobuf_enc
  # Uncomment below to use custom built protobuf.
  # -L${APKMAN_ROOT}/apkbuild/pkgs/usr/lib
  -L${APKMAN_ROOT}/usr/lib
  # Full version of protobuf.
  libprotobuf.a
  libstdc++.a
  oelibcxx # For libunwind which has been patched for enclaves
  oelibc
  # Use apkman's ld to avoid bug with Ubuntu 18.04's binutils.
  -fuse-ld=${CMAKE_CURRENT_SOURCE_DIR}/../../../utils/ld
  # Warn unresolved symbols instead of failing.
  -Wl,--warn-unresolved-symbols)
