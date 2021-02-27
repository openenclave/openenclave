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

# Compile cpp20 test code using apkman's clang compiler.
# Current machine's c++ compiler may not be up to date to compile
# cpp++20.
add_custom_command(
  OUTPUT main.o
  COMMAND apkman exec g++ -o main.o -g -Og -c -fcoroutines -std=c++20
          ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp
  DEPENDS main.cpp apkman-init)

add_enclave(
  TARGET
  cpp20_enc
  UUID
  71b0822f-42a3-4543-a97c-ca491f76b82c
  SOURCES
  enc.cpp
  main.o
  ${CMAKE_CURRENT_BINARY_DIR}/test_t.c)

enclave_include_directories(cpp20_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(
  cpp20_enc
  -nostdlib
  # Add library path and libraries.
  -L${APKMAN_ROOT}/usr/lib
  libstdc++.a
  oeencpthread
  libunwind # For libunwind which has been patched for enclaves
  oelibc
  # Use apkman's ld to avoid bug with Ubuntu 18.04's binutils.
  -fuse-ld=${CMAKE_CURRENT_SOURCE_DIR}/../../../utils/ld
  # Emit warnings for unresolved symbols.
  -Wl,--warn-unresolved-symbols)
