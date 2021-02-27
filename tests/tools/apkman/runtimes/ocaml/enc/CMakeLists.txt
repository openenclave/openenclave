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
  ocaml
  COMMAND apkman add ocaml
  DEPENDS apkman-init)

add_custom_command(
  COMMAND apkman exec /bin/bash ${CMAKE_CURRENT_SOURCE_DIR}/build.sh
  DEPENDS lexer.mll parser.mly program.ml modwrap.c
  OUTPUT ocamlprogram.a)

add_enclave(
  TARGET
  ocaml_enc
  UUID
  71b0822f-42a3-4543-a97c-ca491f76b82c
  SOURCES
  enc.c
  stubs.c
  ocamlprogram.a
  ${CMAKE_CURRENT_BINARY_DIR}/test_t.c)

add_dependencies(ocaml_enc ocaml)

enclave_include_directories(ocaml_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

enclave_link_libraries(
  ocaml_enc
  -L${CMAKE_CURRENT_BINARY_DIR}
  -l:ocamlprogram.a
  oelibc
  # Use apkman's ld to avoid bug with Ubuntu 18.04's binutils.
  -fuse-ld=${CMAKE_CURRENT_SOURCE_DIR}/../../../utils/ld
  -Wl,--warn-unresolved-symbols)
