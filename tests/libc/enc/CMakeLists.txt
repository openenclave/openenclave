# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.


# Include the libc tests wrappers:
include(../tests.cmake)

# Generate wrappers for libc tests.
execute_process(
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/wrap_tests.sh
        "${PROJECT_SOURCE_DIR}"
        "${CMAKE_CURRENT_BINARY_DIR}"
        "${LIBC_TESTS}")

oeedl_file(../libc.edl enclave gen)

add_enclave(TARGET libc_enc
    SOURCES
    enc.c
    ${CMAKE_CURRENT_BINARY_DIR}/tests.c
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
