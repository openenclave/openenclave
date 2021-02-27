# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../test.edl)

add_custom_command(
  OUTPUT test_t.h test_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR} --search-path
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../utils)

add_enclave(
  TARGET
  curl_enc
  UUID
  71b0822f-42a3-4543-a97c-ca491f76b82c
  SOURCES
  enc.c
  # Necessary stubs for curl.
  stubs.c
  ${CMAKE_CURRENT_BINARY_DIR}/test_t.c)

add_custom_target(
  curl
  COMMAND apkman add curl-dev curl-static nghttp2-static brotli-static
          zlib-static openssl-libs-static
  DEPENDS apkman-init)

add_dependencies(curl_enc curl)

enclave_include_directories(
  curl_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
  # Include path for libcurl.
  ${APKMAN_ROOT}/usr/include)

enclave_compile_options(
  curl_enc
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
  curl_enc
  -nostdlib
  # Uncomment below line to use custom built package.
  # -L${APKMAN_ROOT}/apkbuild/pkgs/usr/lib
  -L${APKMAN_ROOT}/usr/lib
  -L${APKMAN_ROOT}/lib
  # libcurl and dependencies.
  libcurl.a
  libz.a
  libnghttp2.a
  libssl.a
  libbrotlidec-static.a
  libbrotlicommon-static.a
  # Use OE's openssl which has been patched to work well within enclaves.
  oecryptoopenssl
  # For missing crypto functionality use libcrpto.a.
  libcrypto.a
  # OE libraries needed for sockets, epoll, filesystem etc.
  oelibcxx
  oelibc
  oeencpthread
  oehostepoll
  oehostfs
  oehostsock
  oehostresolver
  # Use apkman's linker to avoid binutils bug:
  # "unable to initialize decompress status for section .debug_info"
  -fuse-ld=${CMAKE_CURRENT_SOURCE_DIR}/../../../utils/ld
  
  # Allow missing symbols for development.
  -Wl,--warn-unresolved-symbols)
