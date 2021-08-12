# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../test.edl)

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

if (OE_SGX)
  add_custom_target(zlib COMMAND oeapkman add zlib-dev zlib-static)
else ()
  add_custom_target(zlib COMMAND oeapkman --optee add zlib-dev zlib-static)
endif ()

add_dependencies(zlib_enc zlib)

enclave_include_directories(
  zlib_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
  # zlib include paths.
  ${APKMAN_ROOT}/usr/include)

if (OE_SGX)
  enclave_compile_options(
    zlib_enc PRIVATE -Wno-implicit-int-conversion -Wno-bitwise-op-parentheses
    -Wno-shift-op-parentheses -Wno-shorten-64-to-32)
else ()
  enclave_compile_options(zlib_enc PRIVATE -Wno-conversion -Wno-parentheses)
endif ()

enclave_link_libraries(zlib_enc -static -L${APKMAN_ROOT}/lib -lz oelibc
                       oehostfs)
