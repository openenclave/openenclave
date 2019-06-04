# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


# Include the libc tests wrappers:
include(../tests.cmake)

# Generate wrappers for libc tests.
foreach(test_file ${LIBC_TESTS})
  string(MAKE_C_IDENTIFIER ${test_file} test_name)
  list(APPEND test_dependencies ${CMAKE_CURRENT_BINARY_DIR}/${test_file})
  configure_file(include.c.in ${test_file})
  string(APPEND run_test "\
    extern int ${test_name}(int argc, const char* argv[]);\n\
    ret += run_test(\"${test_name}\", ${test_name});\n")
endforeach()

configure_file(tests.c.in tests.c)

oeedl_file(../libc.edl enclave gen)

add_enclave(TARGET libc_enc
    SOURCES
    enc.c
    ${CMAKE_CURRENT_BINARY_DIR}/tests.c
    ${test_dependencies}
    ../../../3rdparty/musl/libc-test/src/common/mtest.c
    ../../../3rdparty/musl/libc-test/src/common/rand.c
    ../../../3rdparty/musl/libc-test/src/functional/tls_align_dso.c
    ${LIBC_TESTS}
    ${gen})

target_compile_options(libc_enc PRIVATE
    -Wno-error
    -Wno-unknown-pragmas
    -Wno-unused-function
    -Wno-return-type
    -Wno-macro-redefined
    -Wno-unused-variable
    -Wno-literal-range
    -Wno-missing-braces
    -Wno-writable-strings)

target_include_directories(
    libc_enc PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    .
    ../../../3rdparty/musl/libc-test/src/common)

target_link_libraries(libc_enc
    oelibc oehostfs oehostsock oehostresolver)
