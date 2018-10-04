# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include(add_enclave_executable)

# Generate the test sources.
execute_process(
    COMMAND ${CMAKE_CURRENT_LIST_DIR}/gentests.sh
    ${CMAKE_CURRENT_LIST_DIR}/../tests.supported
    ${CMAKE_CURRENT_BINARY_DIR})

FILE(GLOB TESTS ${CMAKE_CURRENT_BINARY_DIR}/*.c)

add_executable(
    libc_enc 
    enc.c
    ../../../3rdparty/musl/libc-test/src/common/mtest.c
    ../../../3rdparty/musl/libc-test/src/common/rand.c
    ../../../3rdparty/musl/libc-test/src/functional/tls_align_dso.c
    ${TESTS})

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
    ..
    ../../../3rdparty/musl/libc-test/src/common)

target_link_libraries(libc_enc oelibc oeenclave)
