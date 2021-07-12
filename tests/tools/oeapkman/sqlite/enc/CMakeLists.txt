# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(EDL_FILE ../test.edl)

add_custom_command(
  OUTPUT test_t.h test_t.c
  DEPENDS ${EDL_FILE} edger8r
  COMMAND
    edger8r --trusted ${EDL_FILE} --search-path ${PROJECT_SOURCE_DIR}/include
    ${DEFINE_OE_SGX} --search-path ${CMAKE_CURRENT_SOURCE_DIR})

if (OE_SGX)
  add_custom_target(sqlite COMMAND oeapkman add sqlite-dev sqlite-static)
else ()
  add_custom_target(sqlite COMMAND oeapkman --optee add sqlite-dev
                                   sqlite-static)
endif ()

add_enclave(
  TARGET
  sqlite_enc
  UUID
  4d5d6469-e571-4619-aefe-cc28d839f366
  SOURCES
  enc.c
  main.c
  stubs.c
  ${CMAKE_CURRENT_BINARY_DIR}/test_t.c)

add_dependencies(sqlite_enc sqlite)

enclave_include_directories(
  sqlite_enc PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
  # sqlite include paths.
  ${APKMAN_ROOT}/usr/include)

if (OE_SGX)
  enclave_compile_options(
    sqlite_enc
    PRIVATE
    -Wno-implicit-int-conversion
    -Wno-bitwise-op-parentheses
    -Wno-shift-op-parentheses
    -Wno-shorten-64-to-32
    -Wno-unused-parameter)
else ()
  enclave_compile_options(sqlite_enc PRIVATE -Wno-conversion
                          -Wno-unused-parameter -Wno-parentheses)
endif ()

enclave_link_libraries(sqlite_enc -static -L${APKMAN_ROOT}/usr/lib -lsqlite3
                       oelibc)
