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
  boost
  COMMAND apkman add boost-dev boost-static
  DEPENDS apkman-init)

# Compile boost test code using apkman's clang compiler.
# Current machine's c++ compiler may not be up to date to compile
# boost.
add_custom_command(
  OUTPUT boost.o
  COMMAND apkman exec clang++ -o boost.o -g -Og -c
          ${CMAKE_CURRENT_SOURCE_DIR}/boost.cpp
  DEPENDS boost.cpp boost)

add_enclave(
  TARGET
  boost_enc
  UUID
  71b0822f-42a3-4543-a97c-ca491f76b82c
  SOURCES
  enc.cpp
  boost.o
  ${CMAKE_CURRENT_BINARY_DIR}/test_t.c)

add_dependencies(boost_enc boost)

enclave_include_directories(boost_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(
  boost_enc
  -nostdlib
  # Add library path and libraries.
  -L${APKMAN_ROOT}/usr/lib
  libboost_serialization.a
  libstdc++.a
  # for __umodti3
  -L${APKMAN_ROOT}/usr/lib/gcc/x86_64-alpine-linux-musl/10.2.1
  libgcc.a
  oelibcxx # For libunwind which has been patched for enclaves
  oelibc
  # Use apkman's ld to avoid bug with Ubuntu 18.04's binutils.
  -fuse-ld=${CMAKE_CURRENT_SOURCE_DIR}/../../../utils/ld
  # Emit warnings for unresolved symbols.
  -Wl,--warn-unresolved-symbols)
